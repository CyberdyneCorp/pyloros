//! Periodic email confirmation for an authenticated password login.
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    mfa_challenges::{Binding, ChallengeError},
    signing::SigningIdentity,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use rand::{Rng, RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Delivery-only data. The link token must never be returned to the polling client.
pub struct ConfirmationEmail {
    pub recipient: String,
    pub token: String,
    pub match_code: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

pub enum ConfirmationDecision {
    Continue(Transaction<'static, Postgres>),
    Pending {
        mfa_token: String,
        match_code: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ConfirmationError {
    #[error("challenge storage failed")]
    Storage(#[from] sqlx::Error),
    #[error("could not issue login challenge")]
    Signing(#[from] ChallengeError),
    #[error("confirmation email delivery failed")]
    Delivery,
    #[error("challenge randomness unavailable")]
    Random,
}

pub struct ConfirmationPolicy<'a> {
    pub signer: &'a SigningIdentity,
    pub lifetime: TimeDelta,
    pub origin: SessionOrigin<'a>,
    pub request_id: Option<&'a str>,
}

/// Continue the locked transaction returned by password evaluation.
pub async fn require_if_due<F, E>(
    pool: &PgPool,
    mut tx: Transaction<'static, Postgres>,
    user: Uuid,
    policy: ConfirmationPolicy<'_>,
    send: impl FnOnce(ConfirmationEmail) -> F,
) -> Result<ConfirmationDecision, ConfirmationError>
where
    F: Future<Output = Result<(), E>>,
{
    let now = Utc::now();
    let (email,organization,due)=sqlx::query_as::<_,(String,Option<Uuid>,bool)>(
        "SELECT u.primary_email,u.organization_id,p.magic_link_interval_seconds IS NOT NULL
         AND (u.last_magic_link_at IS NULL OR $2::timestamptz-u.last_magic_link_at >= make_interval(secs => p.magic_link_interval_seconds))
         FROM users u LEFT JOIN auth_policy p ON p.id=1
         WHERE u.id=$1 AND u.is_active AND NOT u.totp_enabled AND u.primary_email IS NOT NULL FOR UPDATE OF u")
        .bind(user).bind(now).fetch_one(&mut *tx).await?;
    if !due {
        return Ok(ConfirmationDecision::Continue(tx));
    }
    let id = Uuid::new_v4();
    let mfa_token = policy
        .signer
        .issue_mfa(user, Binding::EmailLink(id), now, policy.lifetime)?;
    let message = stage(&mut tx, user, id, &email, &policy, now).await?;
    let match_code = message.match_code.clone();
    let subject = AuditSubject {
        user: Some(user),
        email: Some(email),
        organization,
    };
    if send(message).await.is_err() {
        tx.rollback().await?;
        if write_activity(
            pool,
            AuditActivity::MfaChallenge {
                method: "magic_link",
                delivery_failed: true,
            },
            subject,
            policy.origin,
            policy.request_id,
            Utc::now(),
        )
        .await
        .is_err()
        {
            eprintln!("could not record confirmation delivery failure");
        }
        return Err(ConfirmationError::Delivery);
    }
    write_activity(
        &mut *tx,
        AuditActivity::MfaChallenge {
            method: "magic_link",
            delivery_failed: false,
        },
        subject,
        policy.origin,
        policy.request_id,
        Utc::now(),
    )
    .await?;
    tx.commit().await?;
    Ok(ConfirmationDecision::Pending {
        mfa_token,
        match_code,
    })
}

async fn stage(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    id: Uuid,
    email: &str,
    policy: &ConfirmationPolicy<'_>,
    now: DateTime<Utc>,
) -> Result<ConfirmationEmail, ConfirmationError> {
    let mut bytes = [0; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ConfirmationError::Random)?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let message = ConfirmationEmail {
        recipient: email.into(),
        token,
        match_code: OsRng.gen_range(10..100).to_string(),
        ip: policy.origin.ip.map(|ip| ip.to_string()),
        user_agent: policy
            .origin
            .user_agent
            .filter(|v| !v.is_empty())
            .map(|v| v.chars().take(512).collect()),
    };
    let digest = format!("{:x}", Sha256::digest(message.token.as_bytes()));
    let expires = now
        .checked_add_signed(policy.lifetime)
        .ok_or(ChallengeError::Lifetime)?;
    sqlx::query("INSERT INTO magic_link_challenges(id,user_id,token_hash,match_code,status,expires_at,created_at,created_ip,created_user_agent)
        VALUES($1,$2,$3,$4,'pending',$5,$6,$7,$8)")
        .bind(id).bind(user).bind(digest).bind(&message.match_code).bind(expires).bind(now)
        .bind(&message.ip).bind(&message.user_agent).execute(&mut **tx).await?;
    Ok(message)
}
