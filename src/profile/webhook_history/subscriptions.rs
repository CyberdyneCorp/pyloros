use super::*;
use crate::{grant_response::SessionOrigin, key_encryption::KeyEncryptionKey};
use axum::body::Bytes;
use management::Change;
mod input;
use input::Input;

pub(super) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    handle(&state, peer, &headers, None, &bytes).await
}

pub(super) async fn update(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    handle(&state, peer, &headers, Some(&raw), &bytes).await
}

async fn handle(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    raw: Option<&str>,
    bytes: &[u8],
) -> Response {
    let body = match admin_fields::body(headers, bytes) {
        Ok(body) => body,
        Err(e) => return *e,
    };
    let (mut tx, actor, email) = match administrator::operator(state, headers).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let Some(body) = body else { return internal() };
    let id = raw
        .map(|v| crate::query::path_uuid(v, "subscription_id"))
        .transpose();
    let payload = input::parse(&body, raw.is_none());
    let (id, data) = match (id, payload) {
        (Ok(id), Ok(data)) => (id, data),
        (id, data) => {
            return passkeys::validation(
                id.err()
                    .into_iter()
                    .chain(data.err().unwrap_or_default())
                    .collect(),
            );
        }
    };
    let change = match id {
        Some(id) => edit(&mut tx, state.registration.insecure_webhook_http, id, data).await,
        None => {
            insert(
                &mut tx,
                state.registration.key.as_ref(),
                state.registration.insecure_webhook_http,
                data,
            )
            .await
        }
    };
    let (id, change) = match change {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return *e,
        Err(_) => return internal(),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    management::commit_change(tx, actor, email.as_deref(), id, origin, change).await
}

type Mutation = sqlx::Result<Result<(Uuid, Change), Box<Response>>>;

fn check_url(url: &str, allow_http: bool) -> Result<(), Box<Response>> {
    let invalid = |msg| Box::new(problem(StatusCode::UNPROCESSABLE_ENTITY, msg));
    let cleaned = url.replace(['\t', '\r', '\n'], "");
    let (scheme, rest) = cleaned
        .trim_start_matches(|c: char| c <= ' ')
        .split_once(':')
        .unwrap_or(("", ""));
    let authority = rest
        .strip_prefix("//")
        .unwrap_or("")
        .split(['/', '#', '?'])
        .next()
        .unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    crate::oauth_uri::validate_authority(authority, host).map_err(|_| Box::new(internal()))?;
    if !(scheme.eq_ignore_ascii_case("https") || allow_http && scheme.eq_ignore_ascii_case("http"))
    {
        return Err(invalid("URL scheme must be https"));
    }
    if authority.contains('@') {
        return Err(invalid("URL must not embed credentials"));
    }
    if host.is_empty() || host.starts_with(':') {
        return Err(invalid("URL must include a host"));
    }
    let tail = host.split_once(']').map_or(host, |(_, tail)| tail);
    if let Some((_, port)) = tail.split_once(':')
        && !port.is_empty()
        && (!port.bytes().all(|v| v.is_ascii_digit()) || port.parse::<u16>().is_err())
    {
        return Err(invalid("URL port is invalid"));
    }
    Ok(())
}

async fn conflict(tx: &mut Tx<'_>, name: &str, id: Uuid) -> sqlx::Result<bool> {
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM webhook_subscriptions WHERE name=$1 AND id<>$2)")
        .bind(name)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
}
fn duplicate() -> Box<Response> {
    Box::new(problem(StatusCode::CONFLICT, "Webhook name already in use"))
}

async fn insert(
    tx: &mut Tx<'_>,
    key: Option<&KeyEncryptionKey>,
    allow_http: bool,
    data: Input,
) -> Mutation {
    let (Some(name), Some(url), Some(events)) = (data.name, data.url, data.events) else {
        return Ok(Err(Box::new(internal())));
    };
    if let Err(e) = check_url(&url, allow_http) {
        return Ok(Err(e));
    }
    let id = Uuid::new_v4();
    if conflict(tx, &name, id).await? {
        return Ok(Err(duplicate()));
    }
    let Some(key) = key else {
        return Ok(Err(Box::new(internal())));
    };
    let (secret, cipher) = management::generate(key, id)?;
    let sql = format!(
        "INSERT INTO webhook_subscriptions
        (id, name, url, event_types, is_active, description, secret_ciphertext)
        VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {FIELDS}"
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(&name)
        .bind(url)
        .bind(json!(events))
        .bind(data.active.unwrap_or(true))
        .bind(data.description)
        .bind(cipher)
        .fetch_one(&mut **tx)
        .await?;
    let mut value = subscription(&row, Utc::now())?;
    value["secret"] = secret.into();
    Ok(Ok((
        id,
        Change {
            action: "webhook.create",
            metadata: json!({"name":name,"event_types":events}),
            response: (StatusCode::CREATED, Json(value)).into_response(),
        },
    )))
}

async fn edit(tx: &mut Tx<'_>, allow_http: bool, id: Uuid, data: Input) -> Mutation {
    let Some(row) = load(tx, id).await? else {
        return Ok(Err(Box::new(missing())));
    };
    validate_stored(&row)?;
    if let Some(name) = &data.name
        && name != row.try_get::<&str, _>("name")?
        && conflict(tx, name, id).await?
    {
        return Ok(Err(duplicate()));
    }
    if let Some(url) = &data.url
        && let Err(e) = check_url(url, allow_http)
    {
        return Ok(Err(e));
    }
    let sql = format!(
        "UPDATE webhook_subscriptions SET
        name = coalesce($2, name), url = coalesce($3, url),
        event_types = coalesce($4, event_types), is_active = coalesce($5, is_active),
        description = CASE WHEN $6::text IS NULL THEN description ELSE nullif($6, '') END,
        updated_at = now()
        WHERE id = $1 AND (name, url, event_types, is_active, description) IS DISTINCT FROM
        (coalesce($2, name), coalesce($3, url), coalesce($4, event_types), coalesce($5, is_active),
         CASE WHEN $6::text IS NULL THEN description ELSE nullif($6, '') END)
        RETURNING {FIELDS}"
    );
    let updated = sqlx::query(&sql)
        .bind(id)
        .bind(data.name)
        .bind(data.url)
        .bind(data.events.map(|events| json!(events)))
        .bind(data.active)
        .bind(data.description)
        .fetch_optional(&mut **tx)
        .await?;
    let current = match updated {
        Some(row) => row,
        None => load(tx, id).await?.ok_or(sqlx::Error::RowNotFound)?,
    };
    let value = subscription(&current, Utc::now())?;
    let metadata = json!({"name":value["name"],"changed":data.changed});
    Ok(Ok((
        id,
        Change {
            action: "webhook.update",
            metadata,
            response: Json(value).into_response(),
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_fields_preserve_null_and_normalize_events() {
        let fields=input::parse(&json!({"name":null,"description":"","extra":3,"event_types":["user.deleted","role.granted","user.deleted"],"is_active":"off"}),false).unwrap();
        assert_eq!(
            fields.changed,
            ["description", "event_types", "is_active", "name"]
        );
        assert_eq!(fields.events.unwrap(), ["role.granted", "user.deleted"]);
        assert_eq!(fields.name, None);
        assert_eq!(fields.description.as_deref(), Some(""));
        assert_eq!(fields.active, Some(false));
        let issues = input::parse(&json!({"event_types":[false,0],"name":""}), true).unwrap_err();
        assert_eq!(issues.len(), 4);
        assert_eq!(issues[3]["loc"], json!(["body", "event_types", 1]));
    }

    #[test]
    fn destination_policy_preserves_custom_ports_and_restricts_http() {
        for url in ["https://receiver:65535/path", "HTTPS://[::1]:443/hook"] {
            assert!(check_url(url, false).is_ok());
        }
        for url in [
            "https://:443",
            "https://receiver:65536",
            "https://receiver:x",
            "https://user@receiver",
            "https://[::1",
            "http://receiver",
        ] {
            assert!(check_url(url, false).is_err());
        }
        assert!(check_url("http://receiver", true).is_ok());
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn creation_and_partial_edit_preserve_secret_and_skip_unchanged_writes() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "CREATE TEMP TABLE webhook_subscriptions(id uuid PRIMARY KEY,name text UNIQUE,url text,
            description text,event_types jsonb,is_active bool,secret_ciphertext bytea,
            previous_secret_expires_at timestamptz,created_at timestamptz DEFAULT now(),
            updated_at timestamptz DEFAULT now())",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let key = KeyEncryptionKey::new("synthetic subscription test master key").unwrap();
        let create = input::parse(
            &json!({"name":"Receiver","url":"https://test.invalid","event_types":["role.revoked"]}),
            true,
        )
        .unwrap();
        let (id, change) = insert(&mut tx, Some(&key), false, create)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(change.response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(change.response.into_body(), 8192)
            .await
            .unwrap();
        let created: Value = serde_json::from_slice(&body).unwrap();
        assert!(created["secret"].as_str().unwrap().starts_with("whsec_"));
        sqlx::query("UPDATE webhook_subscriptions SET updated_at='2000-01-01Z' WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
        let snapshot = sqlx::query_as::<_, (Vec<u8>, String)>(
            "SELECT secret_ciphertext,updated_at::text FROM webhook_subscriptions WHERE id=$1",
        );
        let (cipher, prior) = snapshot.bind(id).fetch_one(&mut *tx).await.unwrap();
        let patch = input::parse(&json!({"is_active":null,"name":"Receiver"}), false).unwrap();
        let (_, change) = edit(&mut tx, false, id, patch).await.unwrap().unwrap();
        assert_eq!(change.metadata["changed"], json!(["is_active", "name"]));
        let patch =
            input::parse(&json!({"description":"updated","is_active":false}), false).unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT updated_at::text FROM webhook_subscriptions")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            prior
        );
        let (_, change) = edit(&mut tx, false, id, patch).await.unwrap().unwrap();
        let body = axum::body::to_bytes(change.response.into_body(), 8192)
            .await
            .unwrap();
        let edited: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(edited["description"], "updated");
        assert_eq!(edited["is_active"], false);
        assert!(edited.get("secret").is_none());
        assert_eq!(
            sqlx::query_scalar::<_, Vec<u8>>("SELECT secret_ciphertext FROM webhook_subscriptions")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            cipher
        );
    }
}
