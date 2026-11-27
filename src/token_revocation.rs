//! Apply a verified OAuth credential to the authenticated client's revocation transaction.
mod verify;
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Construct only after validating the signature, issuer, lifetime and token type.
/// A refresh credential's owner comes from its PostgreSQL grant record.
pub enum VerifiedToken {
    Access {
        id: Uuid,
        expires: DateTime<Utc>,
        client: Option<String>,
        user: Uuid,
    },
    Service {
        id: Uuid,
        expires: DateTime<Utc>,
        client: String,
    },
    Refresh {
        id: Uuid,
        session: Uuid,
        user: Uuid,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Revoked,
    DifferentOwner,
    Unknown,
}

pub(crate) async fn revoke_session(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET revoked_at=$2 WHERE id=$1")
        .bind(id)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at=$2 WHERE session_id=$1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) async fn deny_token(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    expires: DateTime<Utc>,
    client: Option<&str>,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO revoked_tokens(jti, expires_at, client_id, reason, revoked_at)
                 VALUES ($1,$2,$3,$4,$5) ON CONFLICT(jti) DO NOTHING",
    )
    .bind(id)
    .bind(expires)
    .bind(client)
    .bind(reason)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The caller commits successful changes with their audit event.
pub async fn revoke(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
    token: &VerifiedToken,
    now: DateTime<Utc>,
) -> Result<Outcome, sqlx::Error> {
    let (id, expires, owner) = match token {
        VerifiedToken::Refresh { id, session, .. } => {
            let owner = sqlx::query_scalar::<_, Option<String>>(
                "SELECT client_id FROM refresh_tokens WHERE jti=$1",
            )
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?;
            let Some(owner) = owner else {
                return Ok(Outcome::Unknown);
            };
            if owner.as_deref() != Some(client) {
                return Ok(Outcome::DifferentOwner);
            }
            revoke_session(tx, *session, now).await?;
            return Ok(Outcome::Revoked);
        }
        VerifiedToken::Access {
            id,
            expires,
            client,
            ..
        } => (*id, *expires, client.as_deref()),
        VerifiedToken::Service {
            id,
            expires,
            client,
        } => (*id, *expires, Some(client.as_str())),
    };
    if owner != Some(client) {
        return Ok(Outcome::DifferentOwner);
    }
    deny_token(tx, id, expires, owner, "revocation", now).await?;
    Ok(Outcome::Revoked)
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    Invalid,
    Expired,
    Unsupported,
}
