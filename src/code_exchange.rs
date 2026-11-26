//! Grant checks used after client authentication and grant authorization.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::authorization_codes::{Grant, StoredCode, claim, find};

pub struct ExchangeRequest<'a> {
    pub authenticated_client: &'a str,
    pub code: &'a str,
    pub verifier: &'a str,
    pub redirect_uri: Option<&'a str>,
    pub resources: &'a [String],
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    MissingCode,
    MissingVerifier,
    UnknownCode,
    Replayed,
    Expired,
    RedirectMismatch,
    InvalidTarget,
    InvalidProof,
    UserUnavailable,
}

pub enum Exchange {
    Granted(Box<Grant>),
    Refused(Refusal),
}

fn check_bindings(
    code: &StoredCode,
    req: &ExchangeRequest<'_>,
    now: DateTime<Utc>,
) -> Result<(), Refusal> {
    if code.grant.expires_at < now {
        return Err(Refusal::Expired);
    }
    if req.redirect_uri != Some(code.grant.redirect_uri.as_str()) {
        return Err(Refusal::RedirectMismatch);
    }
    match req.resources {
        [] => {}
        [resource] if Some(resource.as_str()) == code.grant.resource.as_deref() => {}
        _ => return Err(Refusal::InvalidTarget),
    }
    let proof = URL_SAFE_NO_PAD.encode(Sha256::digest(req.verifier.as_bytes()));
    if code.challenge_method != "S256"
        || !req.verifier.is_ascii()
        || !bool::from(proof.as_bytes().ct_eq(code.grant.challenge.as_bytes()))
    {
        return Err(Refusal::InvalidProof);
    }
    Ok(())
}

async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    session: Option<Uuid>,
    now: DateTime<Utc>,
) -> Result<Exchange, sqlx::Error> {
    if let Some(id) = session {
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
    }
    Ok(Exchange::Refused(Refusal::Replayed))
}

/// Use a READ COMMITTED transaction. Commit a replay refusal to retain revocation.
/// On success, create the session and issue its tokens before committing.
pub async fn redeem(
    tx: &mut Transaction<'_, Postgres>,
    req: &ExchangeRequest<'_>,
    session: Uuid,
    now: DateTime<Utc>,
) -> Result<Exchange, sqlx::Error> {
    if req.code.is_empty() {
        return Ok(Exchange::Refused(Refusal::MissingCode));
    }
    if req.verifier.is_empty() {
        return Ok(Exchange::Refused(Refusal::MissingVerifier));
    }
    let Some(stored) = find(tx, req.code, req.authenticated_client).await? else {
        return Ok(Exchange::Refused(Refusal::UnknownCode));
    };
    if stored.consumed_at.is_some() {
        return replay(tx, stored.session_id, now).await;
    }
    if let Err(reason) = check_bindings(&stored, req, now) {
        return Ok(Exchange::Refused(reason));
    }
    let active = sqlx::query_scalar::<_, bool>("SELECT is_active FROM users WHERE id=$1")
        .bind(stored.grant.user_id)
        .fetch_optional(&mut **tx)
        .await?;
    if active != Some(true) {
        return Ok(Exchange::Refused(Refusal::UserUnavailable));
    }
    if claim(tx, stored.id, session).await? {
        return Ok(Exchange::Granted(Box::new(stored.grant)));
    }
    let winner = find(tx, req.code, req.authenticated_client).await?;
    replay(tx, winner.and_then(|row| row.session_id), now).await
}
