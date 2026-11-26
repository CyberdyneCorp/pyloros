//! Client authentication for the authorization-code exchange.
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};
use tokio::sync::Semaphore;

use crate::code_exchange::Refusal;

// Each stored hash selects its own memory cost. Bound aggregate work per process.
static HASH_JOBS: Semaphore = Semaphore::const_new(2);

fn matches(secret: &[u8], encoded: &str) -> bool {
    PasswordHash::new(encoded)
        .is_ok_and(|hash| Argon2::default().verify_password(secret, &hash).is_ok())
}

async fn verify_secret(
    secret: &str,
    current: String,
    previous: Option<String>,
) -> Result<bool, sqlx::Error> {
    let permit = HASH_JOBS
        .acquire()
        .await
        .expect("process-wide semaphore stays open");
    let secret = secret.to_owned();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        matches(secret.as_bytes(), &current)
            || previous.is_some_and(|hash| matches(secret.as_bytes(), &hash))
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
