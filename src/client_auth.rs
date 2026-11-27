//! Client authentication for the authorization-code exchange.
use crate::passwords::{matches_argon2, password_worker};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};

use crate::code_exchange::Refusal;

async fn verify_secret(
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

pub(crate) async fn check_client(
    tx: &mut Transaction<'_, Postgres>,
    client_id: &str,
    secret: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Option<Refusal>, sqlx::Error> {
    if client_id.is_empty() {
        return Ok(Some(Refusal::MissingClient));
    }
    let registration = sqlx::query(
        "SELECT client_type, grant_types, secret_hash,
        CASE WHEN previous_secret_expires_at > $2 THEN previous_secret_hash END AS grace_hash
        FROM oauth_clients WHERE client_id=$1 AND active",
    )
    .bind(client_id)
    .bind(now)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(client) = registration else {
        return Ok(Some(Refusal::UnknownClient));
    };
    match client.try_get::<&str, _>("client_type")? {
        "public" => {}
        "confidential" => {
            let Some(value) = secret.filter(|s| !s.is_empty()) else {
                return Ok(Some(Refusal::BadClientSecret));
            };
            if !verify_secret(
                value,
                client.try_get("secret_hash")?,
                client.try_get("grace_hash")?,
            )
            .await?
            {
                return Ok(Some(Refusal::BadClientSecret));
            }
        }
        _ => return Ok(Some(Refusal::UnknownClient)),
    }
    let grants: &str = client.try_get("grant_types")?;
    Ok((!grants
        .split_ascii_whitespace()
        .any(|grant| grant == "authorization_code"))
    .then_some(Refusal::UnauthorizedClient))
}
