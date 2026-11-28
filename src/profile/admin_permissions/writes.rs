//! Mutate a client catalog and append its actor audit in one transaction.
use super::*;
use crate::{
    browser_prompt::quoted_string,
    grant_response::SessionOrigin,
    login_http::problem,
    request_json::{fields, iam_document},
};
use serde_json::value::RawValue;

#[derive(Deserialize)]
pub(in crate::profile) struct CatalogPath {
    client_id: Option<String>,
}

#[derive(Deserialize)]
pub(in crate::profile) struct PermissionPath {
    client_id: Option<String>,
    key: String,
}

enum Edit<'a> {
    Create(Option<&'a RawValue>),
    Delete(&'a str),
}

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(path): Path<CatalogPath>,
    bytes: axum::body::Bytes,
) -> Response {
    let raw = match iam_document::document(&headers, &bytes) {
        Ok(raw) => raw,
        Err(r) => return *r,
    };
    edit(
        &state,
        peer,
        &headers,
        path.client_id,
        Edit::Create(raw.as_deref()),
    )
    .await
    .unwrap_or_else(|_| internal())
}

pub(in crate::profile) async fn remove(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(path): Path<PermissionPath>,
) -> Response {
    if method != Method::DELETE {
        let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
        return r;
    }
    edit(
        &state,
        peer,
        &headers,
        path.client_id,
        Edit::Delete(&path.key),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn edit(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    requested_client: Option<String>,
    edit: Edit<'_>,
) -> Result<Response, sqlx::Error> {
    let (mut tx, caller) =
        match delegated::CatalogCaller::authorize(state, headers, requested_client).await {
            Ok(result) => result,
            Err(error) => return Ok(*error),
        };
    let client = caller.client.as_str();
    if let Some(chain) = state.blockchain.provider().await {
        chain.validate_signer()?;
    }
    let (key, description, action) = match edit.definition() {
        Ok(definition) => definition,
        Err(response) => return Ok(*response),
    };
    let active = sqlx::query_scalar::<_, bool>(
        "SELECT active FROM oauth_clients WHERE client_id=$1 FOR NO KEY UPDATE",
    )
    .bind(client)
    .fetch_optional(&mut *tx)
    .await?;
    if active != Some(true) {
        return Ok(unknown_client(client));
    }
    let response = match edit {
        Edit::Create(_) => insert(&mut tx, client, &key, description.as_deref()).await?,
        Edit::Delete(_) => delete(&mut tx, client, &key).await?,
    };
    if response.status().is_success() {
        let origin = SessionOrigin {
            ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
            user_agent: crate::token_http::header(headers, "user-agent"),
        };
        crate::admin_audit::append_sorted_record(
            &mut tx,
            action,
            caller.actor(),
            Some(("client_permission", Some(&format!("{client}:{key}")))),
            &json!({}),
            origin,
        )
        .await?;
        tx.commit().await?;
    }
    Ok(response)
}

impl Edit<'_> {
    fn definition(&self) -> Result<(String, Option<String>, &'static str), Box<Response>> {
        match self {
            Self::Create(None) => Err(Box::new(internal())),
            Self::Create(Some(raw)) => {
                let (key, description) =
                    fields::validate_scalar_document(raw, &["key", "description"], input)?;
                if !valid_key(&key) {
                    return Err(Box::new(problem(
                        StatusCode::BAD_REQUEST,
                        &format!(
                            "invalid permission key {}: must match [a-z0-9][a-z0-9_.:-]{{0,63}}",
                            quoted_string(&key)
                        ),
                    )));
                }
                Ok((key, description, "client_permission.create"))
            }
            Self::Delete(key) => Ok(((*key).to_owned(), None, "client_permission.delete")),
        }
    }
}

fn input(model: Value) -> Result<(String, Option<String>), Vec<Value>> {
    let body = admin_fields::object(&model)?;
    let mut fields = admin_fields::Fields {
        body,
        issues: Vec::new(),
    };
    let key = match body.get("key") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => fields.string("key", None, true),
    };
    let description = fields.string("description", Some(1024), false);
    if fields.issues.is_empty() {
        Ok((key.expect("validated key"), description))
    } else {
        Err(fields.issues)
    }
}

fn valid_key(key: &str) -> bool {
    let slug = key.strip_suffix('\n').unwrap_or(key);
    let letter_digit = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    slug.len() <= 64
        && slug.bytes().next().is_some_and(letter_digit)
        && slug
            .bytes()
            .all(|b| letter_digit(b) || matches!(b, b'_' | b'.' | b':' | b'-'))
}

async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
    key: &str,
    description: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let (count,duplicate):(i64,bool)=sqlx::query_as("SELECT count(*),coalesce(bool_or(key=$2), false) FROM client_permissions WHERE client_id=$1")
        .bind(client).bind(key).fetch_one(&mut **tx).await?;
    let conflict = || {
        problem(
            StatusCode::CONFLICT,
            &format!(
                "permission {} already exists for client {}",
                quoted_string(key),
                quoted_string(client)
            ),
        )
    };
    if duplicate {
        return Ok(conflict());
    }
    if count >= 256 {
        return Ok(problem(
            StatusCode::CONFLICT,
            &format!(
                "catalog full: client {} already has 256 permissions",
                quoted_string(client)
            ),
        ));
    }
    let created:Option<DateTime<Utc>>=sqlx::query_scalar("INSERT INTO client_permissions(id,client_id,key,description) VALUES($1,$2,$3,$4) ON CONFLICT(client_id,key) DO NOTHING RETURNING created_at")
        .bind(Uuid::new_v4()).bind(client).bind(key).bind(description).fetch_optional(&mut **tx).await?;
    let Some(created) = created else {
        return Ok(conflict());
    };
    Ok((StatusCode::CREATED,Json(json!({"client_id":client,"key":key,"description":description,"created_at":timestamp(created)}))).into_response())
}

async fn delete(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
    key: &str,
) -> Result<Response, sqlx::Error> {
    let removed = sqlx::query("DELETE FROM client_permissions WHERE client_id=$1 AND key=$2")
        .bind(client)
        .bind(key)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    if removed == 0 {
        return Ok(problem(
            StatusCode::NOT_FOUND,
            &format!(
                "permission {} not found for client {}",
                quoted_string(key),
                quoted_string(client)
            ),
        ));
    }
    Ok((
        StatusCode::NO_CONTENT,
        [(header::CONTENT_TYPE, "application/json")],
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_overflow_cannot_be_saved_as_an_absent_description() {
        let raw =
            serde_json::from_str::<&RawValue>(r#"{"key":"read","description":1e999}"#).unwrap();
        let response = Edit::Create(Some(raw)).definition().unwrap_err();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn existing_catalog_above_capacity_can_reclaim_a_slot() -> sqlx::Result<()> {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql("CREATE TEMP TABLE client_permissions(id uuid, client_id text, key text, description text,
            created_at timestamptz DEFAULT now(), PRIMARY KEY(client_id,key));
            INSERT INTO client_permissions(client_id,key) SELECT 'app', n::text FROM generate_series(0,256) n;")
            .execute(&mut *tx).await?;
        for key in ["256", "255"] {
            let response = insert(&mut tx, "app", "next", None).await?;
            assert_eq!(response.status(), StatusCode::CONFLICT);
            assert_eq!(
                delete(&mut tx, "app", key).await?.status(),
                StatusCode::NO_CONTENT
            );
        }
        assert_eq!(
            insert(&mut tx, "app", "256", None).await?.status(),
            StatusCode::CREATED
        );
        assert_eq!(
            insert(&mut tx, "app", "next", None).await?.status(),
            StatusCode::CONFLICT
        );
        tx.rollback().await
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn catalog_deletion_cascades_within_one_client_and_can_roll_back() {
        use sqlx::Acquire;
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE client_permissions(id uuid, client_id text, key text, description text, created_at timestamptz DEFAULT now(), PRIMARY KEY(client_id,key));
            CREATE TEMP TABLE client_role_permissions(client_id text, role_key text, permission_key text,
                FOREIGN KEY(client_id,permission_key) REFERENCES client_permissions(client_id,key) ON DELETE CASCADE);")
            .execute(&mut *tx).await.unwrap();
        for client in ["one", "two"] {
            let result = insert(&mut tx, client, "read", None).await.unwrap();
            assert_eq!(result.status(), StatusCode::CREATED);
        }
        assert_eq!(
            insert(&mut tx, "one", "read", None).await.unwrap().status(),
            StatusCode::CONFLICT
        );
        sqlx::query("INSERT INTO client_role_permissions VALUES('one','a','read'),('one','b','read'),('two','a','read')")
            .execute(&mut *tx).await.unwrap();
        let mut write = tx.begin().await.unwrap();
        let removed = delete(&mut write, "one", "read").await.unwrap();
        assert_eq!(removed.status(), StatusCode::NO_CONTENT);
        assert_eq!(removed.headers()[header::CONTENT_TYPE], "application/json");
        assert!(
            axum::body::to_bytes(removed.into_body(), 256)
                .await
                .unwrap()
                .is_empty()
        );
        let owners = "SELECT client_id FROM client_role_permissions ORDER BY client_id";
        assert_eq!(
            sqlx::query_scalar::<_, String>(owners)
                .fetch_all(&mut *write)
                .await
                .unwrap(),
            ["two"]
        );
        write.rollback().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(owners)
                .fetch_all(&mut *tx)
                .await
                .unwrap(),
            ["one", "one", "two"]
        );
    }
}
