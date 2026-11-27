//! Complete the browser half of a CLI login inside the callback transaction.
use super::state::Pending;
use crate::authorization_codes::digest;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use rand::{RngCore, rngs::OsRng};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum CliReturnError {
    #[error("invalid CLI callback instructions")]
    Instructions,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// Call after claiming the state and resolving the user. Publish the redirect after commit.
pub async fn issue(
    tx: &mut Transaction<'_, Postgres>,
    pending: &Pending,
    user: Uuid,
    now: DateTime<Utc>,
) -> Result<String, CliReturnError> {
    let instructions = &pending.instructions;
    let port = instructions
        .cli_port
        .filter(|port| (1024..=65535).contains(port))
        .ok_or(CliReturnError::Instructions)?;
    let challenge = instructions
        .code_challenge
        .as_deref()
        .ok_or(CliReturnError::Instructions)?;
    if instructions.return_mode != "cli" || instructions.frontend_redirect.is_some() {
        return Err(CliReturnError::Instructions);
    }
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let code = URL_SAFE_NO_PAD.encode(secret);
    sqlx::query(
        "INSERT INTO cli_login_codes
        (id,code_hash,user_id,provider,code_challenge,authenticated_at,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(Uuid::new_v4())
    .bind(digest(&code))
    .bind(user)
    .bind(pending.provider())
    .bind(challenge)
    .bind(now)
    .bind(now + TimeDelta::seconds(60))
    .execute(&mut **tx)
    .await?;
    Ok(format!("http://127.0.0.1:{port}/callback?code={code}"))
}
