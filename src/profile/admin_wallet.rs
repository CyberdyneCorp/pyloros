//! Provision the managed key material for an existing account.
use super::*;
use crate::{
    grant_response::SessionOrigin,
    key_encryption::KeyEncryptionKey,
    login_http::problem,
    managed_wallet::ManagedWallet,
    token_http::{client_ip, header as value},
};
use axum::extract::Path;

pub(super) async fn ensure(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let id = match crate::query::path_uuid(&raw, "user_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    provision(
        tx,
        id,
        state.registration.key.as_ref(),
        (actor, email.as_deref()),
        origin,
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn provision(
    mut tx: Transaction<'_, Postgres>,
    id: Uuid,
    key: Option<&KeyEncryptionKey>,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, Box<dyn Error + Send + Sync>> {
    let account = sqlx::query_as::<_, (Option<String>, String)>(
        "SELECT default_wallet_address, extra_metadata::text FROM users WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((address, metadata)) = account else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    let normalized = admin_organizations::normalized_storage(&metadata)?;
    if let Some(address) = address.filter(|address| !address.is_empty()) {
        return Ok(Json(json!({"user_id":id,"address":address,"created":false})).into_response());
    }
    let normalized = normalized
        .map(|doc| crate::stored_json::project_fractions(doc, true))
        .transpose()?;
    let Some(key) = key else {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Wallet encryption key unavailable",
        ));
    };
    let wallet = ManagedWallet::generate(key)?;
    sqlx::query(
        "UPDATE users SET default_wallet_address=$2, public_key=$3, encrypted_private_key=$4,
            extra_metadata=COALESCE($5::text::jsonb,extra_metadata), updated_at=now()
         WHERE id=$1 RETURNING id",
    )
    .bind(id)
    .bind(&wallet.address)
    .bind(wallet.public_key)
    .bind(wallet.encrypted_private_key)
    .bind(normalized)
    .fetch_one(&mut *tx)
    .await?;
    crate::admin_audit::append(
        &mut tx,
        "user.provision_wallet",
        Some(actor),
        ("user", &id.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"user_id":id,"address":wallet.address,"created":true})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn failed_wallet_audit_restores_keys_and_legacy_metadata()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL")?)
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid PRIMARY KEY, default_wallet_address text, public_key text,
            encrypted_private_key bytea, extra_metadata jsonb, updated_at timestamptz);
            CREATE TEMP TABLE audit_chain_head(id int PRIMARY KEY,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text CHECK(action <> 'user.provision_wallet'),
            target_type text,target_id text,extra_metadata jsonb,ip_address inet,user_agent text,
            created_at timestamptz,prev_hash text,row_hash text,actor_user_id uuid,actor_type text,actor_client_id text,actor_email text);")
            .execute(&pool).await?;
        let id = Uuid::new_v4();
        sqlx::query(r#"INSERT INTO users(id,extra_metadata) VALUES($1,'[["old",3]]')"#)
            .bind(id)
            .execute(&pool)
            .await?;
        let err = provision(
            pool.begin().await?,
            id,
            Some(&KeyEncryptionKey::new("wallet fixture")?),
            (Uuid::new_v4(), None),
            SessionOrigin {
                ip: None,
                user_agent: None,
            },
        )
        .await
        .unwrap_err();
        assert!(
            err.downcast_ref::<sqlx::Error>()
                .and_then(sqlx::Error::as_database_error)
                .is_some_and(|e| e.is_check_violation())
        );
        let intact: bool = sqlx::query_scalar(r#"SELECT default_wallet_address IS NULL AND public_key IS NULL
            AND encrypted_private_key IS NULL AND extra_metadata='[["old",3]]'::jsonb AND updated_at IS NULL
            FROM users WHERE id=$1"#).bind(id).fetch_one(&pool).await?;
        assert!(intact);
        Ok(())
    }
}
