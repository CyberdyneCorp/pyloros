//! Apply and publish operator changes to the OAuth scope registry.
use super::*;
use crate::grant_response::SessionOrigin;
use serde_json::Map;

enum Operation<'a> {
    Create,
    Update(&'a str),
    Deactivate(&'a str),
}

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    handle(&state, peer, &headers, Operation::Create, &bytes).await
}

pub(in crate::profile) async fn update(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    handle(&state, peer, &headers, Operation::Update(&name), &bytes).await
}

pub(in crate::profile) async fn deactivate(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle(&state, peer, &headers, Operation::Deactivate(&name), &[]).await
}

async fn handle(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    op: Operation<'_>,
    bytes: &[u8],
) -> Response {
    let body = match admin_fields::body(headers, bytes) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let Some(id) = administrator::identity(state, headers) else {
        return unauthorized();
    };
    let Ok(registry) = catalog(state).await else {
        return internal();
    };
    let (tx, email) = match administrator::session(state, &id).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let Some(body) = body else { return internal() };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    let change = match Change::parse(op, &body) {
        Ok(change) => change,
        Err(response) => return *response,
    };
    change
        .apply(tx, state, registry, (id.user, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

enum Change<'a> {
    Create {
        name: String,
        description: String,
    },
    Update {
        name: &'a str,
        fields: Map<String, Value>,
    },
    Deactivate(&'a str),
}

fn invalid(issues: Vec<Value>) -> Box<Response> {
    Box::new(
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"detail":issues})),
        )
            .into_response(),
    )
}

fn trimmed(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

impl<'a> Change<'a> {
    fn parse(op: Operation<'a>, body: &Value) -> Result<Self, Box<Response>> {
        if let Operation::Deactivate(name) = op {
            return Ok(Self::Deactivate(name));
        }
        let map = admin_fields::object(body).map_err(invalid)?;
        let mut fields = admin_fields::Fields {
            body: map,
            issues: vec![],
        };
        let change = match op {
            Operation::Create => {
                let name = fields.string("name", Some(128), true).unwrap_or_default();
                let description = fields
                    .string("description", Some(1024), true)
                    .unwrap_or_default();
                Self::Create {
                    name: trimmed(&name).into(),
                    description: trimmed(&description).into(),
                }
            }
            Operation::Update(name) => {
                let mut patch = Map::new();
                for key in ["description", "active"] {
                    let Some(value) = map.get(key) else { continue };
                    let normalized = if value.is_null() {
                        Value::Null
                    } else if key == "active" {
                        json!(fields.boolean(key))
                    } else {
                        json!(fields.string(key, Some(1024), true))
                    };
                    patch.insert(key.into(), normalized);
                }
                Self::Update {
                    name,
                    fields: patch,
                }
            }
            Operation::Deactivate(_) => unreachable!(),
        };
        if fields.issues.is_empty() {
            Ok(change)
        } else {
            Err(invalid(fields.issues))
        }
    }

    async fn apply(
        self,
        mut tx: Transaction<'static, Postgres>,
        state: &Profile,
        registry: &crate::discovery::ScopeRegistry,
        actor: (Uuid, Option<&str>),
        origin: SessionOrigin<'_>,
    ) -> Result<Response, sqlx::Error> {
        let (name, action, meta, response) = match self {
            Self::Create { name, description } => {
                if !valid_name(&name) {
                    return Ok(problem(
                        StatusCode::BAD_REQUEST,
                        "scope names must match ^[a-z0-9][a-z0-9._:-]{0,127}$ (no whitespace)",
                    ));
                }
                let exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_scopes WHERE name=$1)")
                        .bind(&name)
                        .fetch_one(&mut *tx)
                        .await?;
                if exists || state.builtin_scopes.contains_key(&name) {
                    return Ok(duplicate(&name));
                }
                let row = sqlx::query_as::<_, ScopeRow>(
                    "INSERT INTO oauth_scopes (name,description,active,created_by_user_id)
                     VALUES ($1,$2,true,$3) RETURNING name,description,active,created_at,updated_at"
                ).bind(&name).bind(description).bind(actor.0).fetch_one(&mut *tx).await?;
                (
                    name,
                    "oauth_scope.create",
                    json!({}),
                    (StatusCode::CREATED, Json(custom(row))).into_response(),
                )
            }
            Self::Update { name, fields } => {
                let row = match edit(
                    &mut tx,
                    state,
                    name,
                    fields
                        .get("description")
                        .and_then(Value::as_str)
                        .map(trimmed),
                    fields.get("active").and_then(Value::as_bool),
                )
                .await?
                {
                    Ok(row) => row,
                    Err(response) => return Ok(*response),
                };
                (
                    name.into(),
                    "oauth_scope.update",
                    Value::Object(fields),
                    Json(custom(row)).into_response(),
                )
            }
            Self::Deactivate(name) => {
                if let Err(response) = edit(&mut tx, state, name, None, Some(false)).await? {
                    return Ok(*response);
                }
                (
                    name.into(),
                    "oauth_scope.delete",
                    json!({}),
                    StatusCode::NO_CONTENT.into_response(),
                )
            }
        };
        crate::admin_audit::append(
            &mut tx,
            action,
            Some(actor),
            ("oauth_scope", &name),
            meta,
            origin,
        )
        .await?;
        registry.commit(tx).await?;
        Ok(response)
    }
}

fn valid_name(name: &str) -> bool {
    let alphanumeric = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    name.bytes().next().is_some_and(alphanumeric)
        && name
            .bytes()
            .all(|b| alphanumeric(b) || b"._:-".contains(&b))
}

fn duplicate(name: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        &format!("scope '{}' already exists", name),
    )
}

async fn edit(
    tx: &mut Transaction<'_, Postgres>,
    state: &Profile,
    name: &str,
    description: Option<&str>,
    active: Option<bool>,
) -> Result<Result<ScopeRow, Box<Response>>, sqlx::Error> {
    if state.builtin_scopes.contains_key(name) {
        let name = crate::browser_prompt::quoted_string(name);
        return Ok(Err(Box::new(problem(
            StatusCode::CONFLICT,
            &format!("built-in scope {name} is read-only"),
        ))));
    }
    let row = sqlx::query_as::<_, ScopeRow>(
        "UPDATE oauth_scopes SET description=coalesce($2,description), active=coalesce($3,active),
        updated_at=CASE WHEN coalesce($2,description)<>description OR coalesce($3,active)<>active THEN now() ELSE updated_at END
        WHERE name=$1 RETURNING name,description,active,created_at,updated_at")
        .bind(name).bind(description).bind(active).fetch_optional(&mut **tx).await?;
    Ok(row.ok_or_else(|| {
        Box::new(problem(
            StatusCode::NOT_FOUND,
            &format!("not found: {name}"),
        ))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_patch_preserves_explicit_nulls_and_normalizes_the_audit_boolean() {
        let body = json!({"description":null, "active":"OFF", "other":true});
        let Change::Update { fields, .. } = Change::parse(Operation::Update("app"), &body).unwrap()
        else {
            panic!("expected scope update")
        };
        assert_eq!(
            Value::Object(fields),
            json!({"description":null,"active":false})
        );
    }
}
