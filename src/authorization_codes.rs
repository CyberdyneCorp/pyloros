//! PostgreSQL adapter for the issuer's authorization-code exchange.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub struct Grant {
    pub client_id: String,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scopes: String,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
    pub nonce: Option<String>,
    pub resource: Option<String>,
    pub auth_time: Option<DateTime<Utc>>,
    pub amr: Option<String>,
}

impl Grant {
    pub(crate) fn sorted_scopes(&self) -> String {
        self.scopes
            .split_ascii_whitespace()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub struct StoredCode {
    pub id: Uuid,
    pub grant: Grant,
    pub challenge_method: String,
    pub consumed_at: Option<DateTime<Utc>>,
    pub session_id: Option<Uuid>,
}

pub(crate) fn digest(code: &str) -> String {
    format!("{:x}", Sha256::digest(code.as_bytes()))
}

pub async fn issue(
    tx: &mut Transaction<'_, Postgres>,
    grant: &Grant,
) -> Result<String, sqlx::Error> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let code = URL_SAFE_NO_PAD.encode(secret);
    sqlx::query(
        "INSERT INTO oidc_authorization_codes
        (id, code_hash, client_id, user_id, redirect_uri, scopes, code_challenge,
         code_challenge_method, expires_at, nonce, resource, auth_time, amr)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'S256',$8,$9,$10,$11,$12)",
    )
    .bind(Uuid::new_v4())
    .bind(digest(&code))
    .bind(&grant.client_id)
    .bind(grant.user_id)
    .bind(&grant.redirect_uri)
    .bind(&grant.scopes)
    .bind(&grant.challenge)
    .bind(grant.expires_at)
    .bind(&grant.nonce)
    .bind(&grant.resource)
    .bind(grant.auth_time)
    .bind(&grant.amr)
    .execute(&mut **tx)
    .await?;
    Ok(code)
}

pub async fn find(
    tx: &mut Transaction<'_, Postgres>,
    code: &str,
    client: &str,
) -> Result<Option<StoredCode>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, client_id, user_id, redirect_uri, scopes, code_challenge,
        code_challenge_method, expires_at, nonce, resource, auth_time, amr, consumed_at, session_id
        FROM oidc_authorization_codes WHERE code_hash=$1 AND client_id=$2",
    )
    .bind(digest(code))
    .bind(client)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| {
        Ok(StoredCode {
            id: r.try_get("id")?,
            challenge_method: r.try_get("code_challenge_method")?,
            consumed_at: r.try_get("consumed_at")?,
            session_id: r.try_get("session_id")?,
            grant: Grant {
                client_id: r.try_get("client_id")?,
                user_id: r.try_get("user_id")?,
                redirect_uri: r.try_get("redirect_uri")?,
                scopes: r.try_get("scopes")?,
                challenge: r.try_get("code_challenge")?,
                expires_at: r.try_get("expires_at")?,
                nonce: r.try_get("nonce")?,
                resource: r.try_get("resource")?,
                auth_time: r.try_get("auth_time")?,
                amr: r.try_get("amr")?,
            },
        })
    })
    .transpose()
}

/// Called after grant checks. Commit in the same transaction as the new session.
pub async fn claim(
    tx: &mut Transaction<'_, Postgres>,
    code_id: Uuid,
    session_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oidc_authorization_codes
        SET consumed_at=clock_timestamp(), session_id=$2 WHERE id=$1 AND consumed_at IS NULL",
    )
    .bind(code_id)
    .bind(session_id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected() == 1)
}
