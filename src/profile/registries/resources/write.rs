//! Register and partially update resources while retaining the operator's submitted audit fields.
use super::*;
use crate::{browser_prompt::quoted_string, grant_response::SessionOrigin};
use serde_json::Map;

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    write(&state, peer, &headers, None, &bytes).await
}

pub(in crate::profile) async fn update(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    write(&state, peer, &headers, Some(&path), &bytes).await
}

async fn write(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    target: Option<&str>,
    bytes: &[u8],
) -> Response {
    let body = match admin_fields::body(headers, bytes) {
        Ok(body) => body,
        Err(r) => return *r,
    };
    let Some(identity) = administrator::identity(state, headers) else {
        return unauthorized();
    };
    let Ok(registry) = catalog(state).await else {
        return internal();
    };
    let (tx, email) = match administrator::session(state, &identity).await {
        Ok(session) => session,
        Err(r) => return *r,
    };
    let Some(body) = body else { return internal() };
    let request = match Request::parse(target, &body) {
        Ok(request) => request,
        Err(issues) => return passkeys::validation(issues),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    request
        .apply(
            tx,
            state,
            registry,
            (identity.user, email.as_deref()),
            origin,
        )
        .await
        .unwrap_or_else(|_| internal())
}

struct Request {
    target: Option<Uuid>,
    fields: Value,
}

impl Request {
    fn parse(target: Option<&str>, body: &Value) -> Result<Self, Vec<Value>> {
        let id = target
            .map(|s| crate::query::path_uuid(s, "entry_id"))
            .transpose();
        let mut issues: Vec<_> = id.as_ref().err().cloned().into_iter().collect();
        let body = match admin_fields::object(body) {
            Ok(map) => map,
            Err(errors) => {
                issues.extend(errors);
                return Err(issues);
            }
        };
        let mut fields = admin_fields::Fields { body, issues };
        let mut values = Map::new();
        if target.is_none() {
            values.insert(
                "resource".into(),
                json!(fields.string("resource", Some(2048), true)),
            );
        }
        if body.contains_key("scopes") {
            values.insert(
                "scopes".into(),
                json!(fields.string_list("scopes", target.is_some())),
            );
        }
        for (key, limit) in [("audience", 255), ("name", 128), ("description", 1024)] {
            if body.contains_key(key) {
                values.insert(key.into(), json!(fields.string(key, Some(limit), false)));
            }
        }
        if target.is_some()
            && let Some(value) = body.get("active")
        {
            let active = if value.is_null() {
                Value::Null
            } else {
                json!(fields.boolean("active"))
            };
            values.insert("active".into(), active);
        }
        if !fields.issues.is_empty() {
            return Err(fields.issues);
        }
        Ok(Self {
            target: id.unwrap(),
            fields: Value::Object(values),
        })
    }

    async fn apply(
        self,
        mut tx: Transaction<'static, Postgres>,
        state: &Profile,
        registry: &crate::discovery::ScopeRegistry,
        actor: (Uuid, Option<&str>),
        origin: SessionOrigin<'_>,
    ) -> Result<Response, sqlx::Error> {
        let saved = match self.target {
            Some(id) => self.patch(&mut tx, registry, id).await?,
            None => self.insert(&mut tx, state, registry, actor.0).await?,
        };
        let row = match saved {
            Ok(row) => row,
            Err(response) => return Ok(*response),
        };
        let (status, action, meta) = if self.target.is_some() {
            (
                StatusCode::OK,
                "oauth_protected_resource.update",
                self.fields,
            )
        } else {
            (
                StatusCode::CREATED,
                "oauth_protected_resource.create",
                json!({"resource":row["resource"],"audience":row["audience"]}),
            )
        };
        let id = row["id"].as_str().expect("UUID column");
        crate::admin_audit::append(
            &mut tx,
            action,
            Some(actor),
            ("oauth_protected_resource", id),
            meta,
            origin,
        )
        .await?;
        registry.commit(tx).await?;
        Ok((status, Json(row)).into_response())
    }

    fn scopes(&self, registry: &crate::discovery::ScopeRegistry) -> Result<Option<String>, String> {
        let Some(items) = self.fields["scopes"].as_array() else {
            return Ok(None);
        };
        let wanted: BTreeSet<_> = items
            .iter()
            .filter_map(Value::as_str)
            .map(mutation::trimmed)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        admin_clients::creation::validate_scopes(&wanted, &registry.catalog.borrow())?;
        Ok(Some(wanted.into_iter().collect::<Vec<_>>().join(" ")))
    }

    fn audience(&self) -> Result<Option<&str>, String> {
        let value = self.fields["audience"].as_str();
        if value.is_some_and(|s| {
            s.is_empty()
                || s.chars()
                    .any(|c| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
        }) {
            return Err("audience must be 1-255 characters with no whitespace".into());
        }
        Ok(value)
    }

    async fn insert(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        state: &Profile,
        registry: &crate::discovery::ScopeRegistry,
        actor: Uuid,
    ) -> Result<Saved, sqlx::Error> {
        let uri = mutation::trimmed(
            self.fields["resource"]
                .as_str()
                .expect("validated resource"),
        );
        if let Err(message) = validate_uri(uri) {
            return Ok(invalid(message));
        }
        let (audience, scopes) = match self
            .audience()
            .and_then(|a| self.scopes(registry).map(|s| (a, s.unwrap_or_default())))
        {
            Ok(values) => values,
            Err(message) => return Ok(invalid(message)),
        };
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM oauth_protected_resources WHERE resource=$1)",
        )
        .bind(uri)
        .fetch_one(&mut **tx)
        .await?;
        if exists || state.configured_resources.scopes.contains_key(uri) {
            return Ok(Err(Box::new(problem(
                StatusCode::CONFLICT,
                &format!("protected resource {} already exists", quoted_string(uri)),
            ))));
        }
        let row = sqlx::query(
            "INSERT INTO oauth_protected_resources(id,resource,scopes,audience,name,description,active,created_by_user_id)
            VALUES ($1,$2,$3,$4,$5,$6,true,$7) RETURNING *",
        )
            .bind(Uuid::new_v4())
        .bind(uri)
        .bind(scopes)
        .bind(audience)
        .bind(self.fields["name"].as_str())
        .bind(self.fields["description"].as_str())
        .bind(actor)
        .try_map(document)
        .fetch_one(&mut **tx)
        .await?;
        Ok(Ok(row))
    }

    async fn patch(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        registry: &crate::discovery::ScopeRegistry,
        id: Uuid,
    ) -> Result<Saved, sqlx::Error> {
        let row = sqlx::query(&format!("{SELECT} WHERE id=$1 FOR UPDATE"))
            .bind(id)
            .try_map(document)
            .fetch_optional(&mut **tx)
            .await?;
        let Some(mut row) = row else {
            return Ok(Err(Box::new(problem(
                StatusCode::NOT_FOUND,
                &format!("not found: {id}"),
            ))));
        };
        let scopes = match self
            .scopes(registry)
            .and_then(|s| self.audience().map(|_| s))
        {
            Ok(s) => s,
            Err(message) => return Ok(invalid(message)),
        };
        for key in ["audience", "description", "name"] {
            if let Some(value) = self.fields.get(key) {
                row[key] = value.clone();
            }
        }
        let active = self.fields["active"]
            .as_bool()
            .unwrap_or(row["active"] == true);
        let scopes = scopes.unwrap_or_else(|| {
            row["scopes"]
                .as_array()
                .expect("scope list")
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        });
        let row = sqlx::query(
            "UPDATE oauth_protected_resources SET scopes=$2, audience=$3, name=$4, description=$5, active=$6,
            updated_at=CASE WHEN (scopes,audience,name,description,active) IS DISTINCT FROM ($2,$3,$4,$5,$6)
            THEN now() ELSE updated_at END WHERE id=$1 RETURNING *",
        )
            .bind(id)
        .bind(scopes)
        .bind(row["audience"].as_str())
        .bind(row["name"].as_str())
        .bind(row["description"].as_str())
        .bind(active)
        .try_map(document)
        .fetch_one(&mut **tx)
        .await?;
        Ok(Ok(row))
    }
}

type Saved = Result<Value, Box<Response>>;
fn invalid(message: String) -> Saved {
    Err(Box::new(problem(StatusCode::BAD_REQUEST, &message)))
}

fn validate_uri(uri: &str) -> Result<(), String> {
    let cleaned = uri.replace(['\r', '\n', '\t'], "");
    let invalid = || {
        format!(
            "resource must be an https URL without fragment: {}",
            quoted_string(uri)
        )
    };
    let cleaned = cleaned.trim_start_matches(|c: char| c <= ' ');
    let (scheme, rest) = cleaned
        .split_once("://")
        .unwrap_or(("", cleaned.strip_prefix("//").unwrap_or("")));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    validate_authority(authority, host)?;
    if !scheme.eq_ignore_ascii_case("https")
        || host.is_empty()
        || host.starts_with(':')
        || rest
            .split_once('#')
            .is_some_and(|(_, fragment)| !fragment.is_empty())
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_authority(authority: &str, host: &str) -> Result<(), String> {
    use unicode_normalization::UnicodeNormalization;
    if authority.contains(['[', ']']) {
        validate_brackets(authority, host)?;
    }
    if !authority.is_ascii() {
        let bare = authority.replace(['@', ':', '#', '?'], "");
        let normalized: String = bare.nfkc().collect();
        if normalized != bare && normalized.contains(['/', '?', '#', '@', ':']) {
            return Err(format!(
                "netloc {} contains invalid characters under NFKC normalization",
                quoted_string(authority)
            ));
        }
    }
    Ok(())
}

fn validate_brackets(authority: &str, host: &str) -> Result<(), String> {
    if !authority.contains('[') || !authority.contains(']') {
        return Err("Invalid IPv6 URL".into());
    }
    let (address, suffix) = host
        .strip_prefix('[')
        .unwrap_or(host)
        .split_once(']')
        .unwrap_or((host, ""));
    if host.find('[').is_some_and(|i| i != 0) || (!suffix.is_empty() && !suffix.starts_with(':')) {
        return Err("Invalid IPv6 URL".into());
    }
    if let Some(future) = address.strip_prefix('v') {
        return if future.split_once('.').is_some_and(|(version, tail)| {
            !version.is_empty()
                && version.bytes().all(|b| b.is_ascii_hexdigit())
                && !tail.is_empty()
        }) {
            Ok(())
        } else {
            Err("IPvFuture address is invalid".into())
        };
    }
    let not_ip = || {
        format!(
            "{} does not appear to be an IPv4 or IPv6 address",
            quoted_string(address)
        )
    };
    if address.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err("An IPv4 address cannot be in brackets".into());
    }
    let ip = match address.split_once('%') {
        Some((ip, zone)) if !zone.is_empty() && !zone.contains('%') => ip,
        Some(_) => return Err(not_ip()),
        None => address,
    };
    ip.parse::<std::net::Ipv6Addr>()
        .map(|_| ())
        .map_err(|_| not_ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_and_body_validation_errors_follow_request_order() {
        let Err(issues) = Request::parse(
            Some("bad"),
            &json!({"scopes":null,"active":"sometimes","description":8}),
        ) else {
            panic!("invalid update accepted");
        };
        let fields: Vec<_> = issues
            .iter()
            .map(|issue| issue["loc"][1].as_str().unwrap())
            .collect();
        assert_eq!(fields, ["entry_id", "description", "active"]);
    }

    #[test]
    fn resource_authority_and_fragment_validation_preserves_uri_identity() {
        assert!(validate_uri("https://[::1%local]/path#").is_ok());
        assert!(validate_uri("https://[v1.example]/").is_ok());
        assert!(validate_uri("https://server/path#section").is_err());
        assert!(validate_uri("https://server／name/").is_err());
    }
}
