//! OAuth registration lookup and validation of public or confidential clients.
use crate::passwords::{matches_argon2, password_worker};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};

use crate::code_exchange::Refusal;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};

pub(crate) fn opaque<const N: usize>() -> String {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) async fn verify_secret(
    secret: &str,
    current: String,
    previous: Option<String>,
) -> Result<bool, sqlx::Error> {
    let secret = secret.to_owned();
    password_worker(move || {
        matches_argon2(secret.as_bytes(), &current)
            || previous.is_some_and(|hash| matches_argon2(secret.as_bytes(), &hash))
    })
    .await
    .map_err(|_| sqlx::Error::WorkerCrashed)
}

pub(crate) async fn registration(
    tx: &mut Transaction<'_, Postgres>,
    client_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query(
        "SELECT client_type, grant_types, secret_hash,
        CASE WHEN previous_secret_expires_at > $2 THEN previous_secret_hash END AS grace_hash
        FROM oauth_clients WHERE client_id=$1 AND active",
    )
    .bind(client_id)
    .bind(now)
    .fetch_optional(&mut **tx)
    .await
}

pub(crate) async fn authenticates(
    client: &sqlx::postgres::PgRow,
    secret: Option<&str>,
) -> Result<bool, sqlx::Error> {
    match client.try_get::<&str, _>("client_type")? {
        "public" => Ok(true),
        "confidential" => {
            let Some(value) = secret.filter(|s| !s.is_empty()) else {
                return Ok(false);
            };
            verify_secret(
                value,
                client.try_get("secret_hash")?,
                client.try_get("grace_hash")?,
            )
            .await
        }
        _ => Ok(false),
    }
}

pub(crate) async fn check_client(
    tx: &mut Transaction<'_, Postgres>,
    client_id: &str,
    secret: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Option<Refusal>, sqlx::Error> {
    if client_id.is_empty() {
        return Ok(Some(Refusal::MissingClient));
    }
    let registration = registration(tx, client_id, now).await?;
    let Some(client) = registration else {
        return Ok(Some(Refusal::UnknownClient));
    };
    if !matches!(
        client.try_get::<&str, _>("client_type")?,
        "public" | "confidential"
    ) {
        return Ok(Some(Refusal::UnknownClient));
    }
    if !authenticates(&client, secret).await? {
        return Ok(Some(Refusal::BadClientSecret));
    }
    let grants: &str = client.try_get("grant_types")?;
    Ok((!grants
        .split_ascii_whitespace()
        .any(|grant| grant == "authorization_code"))
    .then_some(Refusal::UnauthorizedClient))
}
