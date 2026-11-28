//! Retry identity issuance and commit the outcome with its operator audit.
use super::*;
use crate::{
    chain_settings::{PrepareError, TokenProvider},
    grant_response::SessionOrigin,
    login_http::problem,
};
use axum::extract::Path;
use serde_json::value::RawValue;

#[derive(Serialize)]
struct Outcome {
    success: bool,
    token_id: Option<Box<RawValue>>,
    tx_hash: Option<String>,
    error: Option<String>,
    nft_status: &'static str,
}

fn decimal_id(id: impl std::fmt::Display) -> Box<RawValue> {
    RawValue::from_string(id.to_string()).expect("decimal token identifier")
}

#[derive(Serialize)]
struct MintAudit<'a> {
    error: Option<&'a str>,
    success: bool,
    token_id: Option<&'a RawValue>,
}

impl Outcome {
    fn failed(error: String) -> Self {
        Self {
            success: false,
            token_id: None,
            tx_hash: None,
            error: Some(error),
            nft_status: "failed",
        }
    }
}

async fn mint(provider: TokenProvider, wallet: &str, key: &str) -> Result<Outcome, Box<Response>> {
    match provider {
        TokenProvider::Local(tokens) => {
            let mut tokens = tokens.lock().await;
            tokens.push(0);
            let id = tokens.len();
            Ok(Outcome {
                success: true,
                token_id: Some(decimal_id(id)),
                tx_hash: Some(format!("0xnull{id:064x}")),
                nft_status: "minted",
                error: None,
            })
        }
        TokenProvider::Remote(chain, writes) => {
            let _write = writes.lock().await;
            match chain.mint_retry(wallet, key).await {
                Ok((hash, id)) => Ok(Outcome {
                    success: true,
                    token_id: id.map(decimal_id),
                    tx_hash: Some(hash),
                    error: None,
                    nft_status: "minted",
                }),
                Err(
                    PrepareError::Argument(detail)
                    | PrepareError::Rpc(detail)
                    | PrepareError::Reverted(detail),
                ) => Ok(Outcome::failed(detail)),
                _ => Err(Box::new(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Blockchain transaction submission unavailable",
                ))),
            }
        }
    }
}

pub(in crate::profile) async fn retry(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Ok(provider) = state.blockchain.token_provider().await else {
        return internal();
    };
    let id = match crate::query::path_uuid(&raw, "user_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    store(tx, provider, id, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn store(
    mut tx: Transaction<'_, Postgres>,
    provider: TokenProvider,
    id: Uuid,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let row = sqlx::query_as::<_, (Option<String>, Option<String>, String)>(
        "SELECT default_wallet_address,public_key,extra_metadata::text FROM users WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((wallet, key, metadata)) = row else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    let normalized = admin_organizations::normalized_storage(&metadata)?;
    let outcome = match (wallet.as_deref(), key.as_deref()) {
        (Some(wallet), Some(key)) if !wallet.is_empty() && !key.is_empty() => {
            if let TokenProvider::Remote(chain, _) = &provider {
                chain.lock_signer(&mut tx).await?;
            }
            let outcome = match mint(provider, wallet, key).await {
                Ok(result) => result,
                Err(response) => return Ok(*response),
            };
            save_metadata(
                &mut tx,
                id,
                normalized.as_deref().unwrap_or(&metadata),
                &outcome,
            )
            .await?;
            outcome
        }
        _ => Outcome::failed("user has no wallet/keypair".into()),
    };
    crate::admin_audit::append_sorted_record(
        &mut tx,
        "blockchain.nft_retry",
        crate::admin_audit::Actor::User(Some(actor)),
        Some(("user", Some(&id.to_string()))),
        &MintAudit {
            error: outcome.error.as_deref(),
            success: outcome.success,
            token_id: outcome.token_id.as_deref(),
        },
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(outcome).into_response())
}

async fn save_metadata(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    metadata: &str,
    outcome: &Outcome,
) -> Result<(), sqlx::Error> {
    // A completed retry applies its outcome to the snapshot from before the provider call.
    sqlx::query(
        "WITH patch AS (SELECT ($2::text::jsonb - 'nft_error') || CASE WHEN $3 THEN
              jsonb_build_object('nft_status','minted','nft_token_id',$4::text::jsonb,'nft_tx_hash',$5::text)
            ELSE jsonb_build_object('nft_status','failed','nft_error',$6::text) END AS value)
         UPDATE users SET extra_metadata=patch.value, updated_at=now() FROM patch
         WHERE id=$1 AND extra_metadata IS DISTINCT FROM patch.value",
    )
    .bind(id)
    .bind(metadata)
    .bind(outcome.success)
    .bind(outcome.token_id.as_deref().map(RawValue::get))
    .bind(&outcome.tx_hash)
    .bind(&outcome.error)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_settings::{ChainSettings, Update};

    #[tokio::test]
    async fn replacing_settings_starts_a_new_local_token_sequence() {
        let settings = ChainSettings::default();
        let earlier = settings.token_provider().await.unwrap();
        let mint_next = || async {
            let provider = settings.token_provider().await.unwrap();
            mint(provider, "wallet", "key")
                .await
                .unwrap()
                .token_id
                .map(|id| id.get().parse::<usize>().unwrap())
        };
        assert_eq!(mint_next().await, Some(1));
        assert_eq!(mint_next().await, Some(2));
        settings.update(Update::default()).await;
        let current = settings.token_provider().await.unwrap();
        assert!(matches!(current.status("2").await, Ok(None)));
        assert!(matches!(earlier.status("2").await, Ok(Some(0))));
        assert_eq!(mint_next().await, Some(1));
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn rejected_audit_rolls_back_retry_metadata() -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid PRIMARY KEY, default_wallet_address text,
                public_key text, extra_metadata jsonb, updated_at timestamptz);
            CREATE TEMP TABLE audit_chain_head(id int PRIMARY KEY,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text CHECK(action <> 'blockchain.nft_retry'),
                target_type text,target_id text,extra_metadata jsonb,ip_address inet,user_agent text,
                created_at timestamptz,prev_hash text,row_hash text,actor_user_id uuid,actor_type text,actor_client_id text,actor_email text);")
            .execute(&pool).await?;
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO users VALUES($1,'wallet','public key','{"nft_error":"old"}',null)"#,
        )
        .bind(id)
        .execute(&pool)
        .await?;
        let settings = ChainSettings::default();
        let outcome = store(
            pool.begin().await?,
            settings.token_provider().await?,
            id,
            (Uuid::new_v4(), None),
            SessionOrigin {
                ip: None,
                user_agent: None,
            },
        )
        .await;
        assert!(
            outcome
                .unwrap_err()
                .as_database_error()
                .unwrap()
                .is_check_violation()
        );
        let metadata: Value = sqlx::query_scalar("SELECT extra_metadata FROM users WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await?;
        assert_eq!(metadata, json!({"nft_error":"old"}));
        assert!(matches!(
            settings.token_provider().await?.status("1").await,
            Ok(Some(0))
        ));
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn completed_retry_uses_metadata_loaded_before_the_provider_call()
    -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid PRIMARY KEY, extra_metadata jsonb, updated_at timestamptz)")
            .execute(&pool).await?;
        let id = Uuid::new_v4();
        let snapshot: String = sqlx::query_scalar("INSERT INTO users VALUES($1,jsonb_build_object('label','before'),now()) RETURNING extra_metadata::text")
            .bind(id).fetch_one(&pool).await?;
        sqlx::query(
            "UPDATE users SET extra_metadata=jsonb_build_object('label','during') WHERE id=$1",
        )
        .bind(id)
        .execute(&pool)
        .await?;
        let mut tx = pool.begin().await?;
        save_metadata(
            &mut tx,
            id,
            &snapshot,
            &Outcome::failed("test refusal".into()),
        )
        .await?;
        tx.commit().await?;
        let result: Value = sqlx::query_scalar("SELECT extra_metadata FROM users WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await?;
        assert_eq!(
            result,
            json!({"label":"before","nft_status":"failed","nft_error":"test refusal"})
        );
        Ok(())
    }
}
