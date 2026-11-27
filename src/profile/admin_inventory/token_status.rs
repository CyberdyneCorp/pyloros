//! Update a user's identity token through its provider and audit the result.
use super::*;
use crate::{
    chain_settings::{PrepareError, TokenProvider},
    grant_response::SessionOrigin,
    login_http::problem,
    request_json::iam_document,
};
use axum::extract::Path;
use serde_json::value::RawValue;
use std::collections::HashMap;

pub(in crate::profile) async fn patch_only() -> Response {
    let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    response
        .headers_mut()
        .insert(header::ALLOW, header::HeaderValue::from_static("PATCH"));
    response
}

pub(in crate::profile) async fn update(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    let doc = match iam_document::document(&headers, &bytes) {
        Ok(doc) => doc,
        Err(response) => return *response,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Ok(provider) = state.blockchain.token_provider().await else {
        return internal();
    };
    let Some(doc) = doc else { return internal() };
    let (id, status) = match input::token_status(&doc, crate::query::path_uuid(&raw, "user_id")) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    store(tx, provider, id, status, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

enum Outcome {
    Changed(&'static str),
    Failed(String),
}

async fn change(
    provider: TokenProvider,
    token: &str,
    status: u8,
) -> Result<Outcome, Box<Response>> {
    match provider {
        TokenProvider::Local(tokens) => {
            let index = token.parse::<usize>().ok().and_then(|id| id.checked_sub(1));
            let mut tokens = tokens.lock().await;
            if let Some(value) = index.and_then(|i| tokens.get_mut(i)) {
                *value = status;
                Ok(Outcome::Changed("0xnullstatus"))
            } else {
                Ok(Outcome::Failed("identity not found".into()))
            }
        }
        TokenProvider::Remote(chain, writes) => {
            let _write = writes.lock().await;
            match chain.prepare_token_status(token, status).await {
                Err(
                    PrepareError::Argument(text)
                    | PrepareError::Rpc(text)
                    | PrepareError::Reverted(text),
                ) => Ok(Outcome::Failed(text)),
                _ => Err(Box::new(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Blockchain transaction submission unavailable",
                ))),
            }
        }
    }
}

#[derive(Serialize)]
struct StatusAudit<'a> {
    new_status: u8,
    success: bool,
    token_id: &'a RawValue,
}

#[derive(Serialize)]
struct StatusResponse<'a> {
    #[serde(flatten)]
    audit: StatusAudit<'a>,
    tx_hash: Option<&'static str>,
    error: Option<String>,
}

async fn store(
    mut tx: Transaction<'_, Postgres>,
    provider: TokenProvider,
    id: Uuid,
    status: u8,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let metadata =
        sqlx::query_scalar::<_, String>("SELECT extra_metadata::text FROM users WHERE id=$1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(metadata) = metadata else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    let normalized = admin_organizations::normalized_storage(&metadata)?;
    let metadata = normalized.as_deref().unwrap_or(&metadata);
    let fields: HashMap<String, &RawValue> =
        serde_json::from_str(metadata).map_err(|e| sqlx::Error::Decode(e.into()))?;
    let Some(token) = fields
        .get("nft_token_id")
        .and_then(|v| user_detail::token::token_number(v))
    else {
        return Ok(problem(StatusCode::BAD_REQUEST, "User has no minted NFT"));
    };
    let (tx_hash, error) = match change(provider, token.get(), status).await {
        Ok(Outcome::Changed(hash)) => {
            let label = ["Active", "Suspended", "Revoked"][usize::from(status)];
            sqlx::query("UPDATE users SET extra_metadata=$2::text::jsonb || jsonb_build_object('nft_status',$3::text), updated_at=now()
                WHERE id=$1 AND extra_metadata IS DISTINCT FROM ($2::text::jsonb || jsonb_build_object('nft_status',$3::text))")
                .bind(id).bind(metadata).bind(label).execute(&mut *tx).await?;
            (Some(hash), None)
        }
        Ok(Outcome::Failed(detail)) => (None, Some(detail)),
        Err(response) => return Ok(*response),
    };
    let audit = StatusAudit {
        new_status: status,
        success: error.is_none(),
        token_id: token,
    };
    crate::admin_audit::append_sorted_record(
        &mut tx,
        "blockchain.nft_status_update",
        Some(actor),
        Some(("user", Some(&id.to_string()))),
        &audit,
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(StatusResponse {
        audit,
        tx_hash,
        error,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_settings::ChainSettings;

    #[tokio::test]
    async fn status_validation_combines_path_and_body_errors_and_keeps_the_original_integer() {
        let raw: &RawValue =
            serde_json::from_str(r#"{"new_status":1208925819614629174706177}"#).unwrap();
        let invalid =
            input::token_status(raw, crate::query::path_uuid("bad", "user_id")).unwrap_err();
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let payload = axum::body::to_bytes(invalid.into_body(), 4096)
            .await
            .unwrap();
        let text = std::str::from_utf8(&payload).unwrap();
        assert!(text.contains("1208925819614629174706177"));
        let doc: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(doc["detail"][0]["loc"], json!(["path", "user_id"]));
        assert_eq!(doc["detail"][1]["ctx"], json!({"le":"2"}));
    }

    #[tokio::test]
    async fn local_status_changes_only_apply_to_issued_tokens() {
        let settings = ChainSettings::default();
        let provider = settings.token_provider().await.unwrap();
        let TokenProvider::Local(tokens) = &provider else {
            panic!("expected local provider")
        };
        tokens.lock().await.push(0);
        let changed = change(settings.token_provider().await.unwrap(), "1", 2)
            .await
            .unwrap();
        assert!(matches!(changed, Outcome::Changed(_)));
        assert!(matches!(provider.status("1").await, Ok(Some(2))));
        let missing = change(
            settings.token_provider().await.unwrap(),
            "1208925819614629174706177",
            1,
        )
        .await
        .unwrap();
        assert!(matches!(missing, Outcome::Failed(_)));
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn audit_preserves_large_token_ids_and_a_rejection_rolls_back_user_metadata()
    -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid PRIMARY KEY,extra_metadata jsonb,updated_at timestamptz);
            CREATE TEMP TABLE audit_chain_head(id int PRIMARY KEY,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text,target_type text,target_id text,extra_metadata jsonb,
              ip_address inet,user_agent text,created_at timestamptz,prev_hash text,row_hash text,actor_user_id uuid,actor_email text);")
            .execute(&pool).await?;
        let id = Uuid::new_v4();
        let settings = ChainSettings::default();
        let origin = || SessionOrigin {
            ip: None,
            user_agent: None,
        };
        sqlx::query(
            r#"INSERT INTO users VALUES($1,'{"nft_token_id":1208925819614629174706177}',null)"#,
        )
        .bind(id)
        .execute(&pool)
        .await?;
        let reply = store(
            pool.begin().await?,
            settings.token_provider().await?,
            id,
            1,
            (id, None),
            origin(),
        )
        .await?;
        assert_eq!(reply.status(), StatusCode::OK);
        let audited: String =
            sqlx::query_scalar("SELECT extra_metadata->>'token_id' FROM admin_action_logs")
                .fetch_one(&pool)
                .await?;
        assert_eq!(audited, "1208925819614629174706177");
        sqlx::raw_sql(r#"UPDATE users SET extra_metadata='{"nft_token_id":1,"nft_status":"minted"}';
            ALTER TABLE admin_action_logs ADD CHECK(action<>'blockchain.nft_status_update') NOT VALID;"#)
            .execute(&pool).await?;
        let provider = settings.token_provider().await?;
        let TokenProvider::Local(tokens) = &provider else {
            panic!("expected local provider")
        };
        tokens.lock().await.push(0);
        let rejected = store(pool.begin().await?, provider, id, 1, (id, None), origin()).await;
        assert!(
            rejected
                .unwrap_err()
                .as_database_error()
                .unwrap()
                .is_check_violation()
        );
        let stored: String =
            sqlx::query_scalar("SELECT extra_metadata->>'nft_status' FROM users WHERE id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(stored, "minted");
        assert!(matches!(
            settings.token_provider().await?.status("1").await,
            Ok(Some(1))
        ));
        Ok(())
    }
}
