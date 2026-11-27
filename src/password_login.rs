//! First-party password decision before the email-link policy and session issuance.
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    mfa_challenges::{Binding, ChallengeError},
    passwords::PasswordScheme,
    signing::SigningIdentity,
};
use chrono::{TimeDelta, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub enum PasswordDecision {
    InvalidCredentials,
    Inactive,
    Totp {
        token: String,
    },
    /// The caller must evaluate the remaining login policies in this transaction.
    Continue {
        user: Uuid,
        verified_at: chrono::DateTime<Utc>,
        transaction: Transaction<'static, Postgres>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("database lookup failed")]
    Database(#[from] sqlx::Error),
    #[error("password verification worker failed")]
    Worker(#[from] tokio::task::JoinError),
    #[error("MFA credential issuance failed")]
    Challenge(#[from] ChallengeError),
    #[error("ambiguous account email")]
    AmbiguousEmail,
}

pub struct PasswordAttempt<'a> {
    pub email: &'a str,
    pub password: String,
    pub origin: SessionOrigin<'a>,
    pub request_id: Option<&'a str>,
}

struct Account {
    id: Uuid,
    primary_email: String,
    organization_id: Option<Uuid>,
    password_hash: Option<String>,
}

impl Account {
    fn subject(&self) -> AuditSubject {
        AuditSubject {
            user: Some(self.id),
            email: Some(self.primary_email.clone()),
            organization: self.organization_id,
        }
    }
}

async fn refuse(
    pool: &PgPool,
    subject: AuditSubject,
    reason: &'static str,
    origin: SessionOrigin<'_>,
    request_id: Option<&str>,
) -> PasswordDecision {
    if write_activity(
        pool,
        AuditActivity::PasswordRefused(reason),
        subject,
        origin,
        request_id,
        Utc::now(),
    )
    .await
    .is_err()
    {
        eprintln!("could not record rejected password login");
    }
    if reason == "inactive" {
        PasswordDecision::Inactive
    } else {
        PasswordDecision::InvalidCredentials
    }
}

/// Call after input validation and rate limiting. No network response is released here.
pub async fn evaluate(
    pool: &PgPool,
    scheme: PasswordScheme,
    signing: &SigningIdentity,
    challenge_lifetime: TimeDelta,
    attempt: PasswordAttempt<'_>,
) -> Result<PasswordDecision, LoginError> {
    let email = attempt.email.trim().to_lowercase();
    let mut accounts = sqlx::query(
        "SELECT id,primary_email,organization_id,password_hash
        FROM users WHERE lower(primary_email)=$1 LIMIT 2",
    )
    .bind(&email)
    .try_map(|row| {
        Ok(Account {
            id: row.try_get("id")?,
            primary_email: row.try_get("primary_email")?,
            organization_id: row.try_get("organization_id")?,
            password_hash: row.try_get("password_hash")?,
        })
    })
    .fetch_all(pool)
    .await?;
    if accounts.len() > 1 {
        return Err(LoginError::AmbiguousEmail);
    }
    let account = accounts.pop();
    let hash = account.as_ref().and_then(|a| a.password_hash.clone());
    let matches = scheme.verify(attempt.password, hash).await?;
    let Some(account) = account else {
        let subject = AuditSubject {
            user: None,
            email: Some(email),
            organization: None,
        };
        return Ok(refuse(
            pool,
            subject,
            "user_not_found",
            attempt.origin,
            attempt.request_id,
        )
        .await);
    };
    if !matches {
        let reason = if account.password_hash.is_none() {
            "password_not_set"
        } else {
            "bad_password"
        };
        return Ok(refuse(
            pool,
            account.subject(),
            reason,
            attempt.origin,
            attempt.request_id,
        )
        .await);
    }
    let verified_at = Utc::now();
    let mut tx = pool.begin().await?;
    let state = sqlx::query_as::<_, (bool, bool, Option<Uuid>, String)>(
        "SELECT is_active,totp_enabled,organization_id,primary_email
        FROM users WHERE id=$1 AND lower(primary_email)=$2 AND password_hash=$3 FOR UPDATE",
    )
    .bind(account.id)
    .bind(email)
    .bind(&account.password_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((active, totp, organization, email)) = state else {
        tx.rollback().await?;
        return Ok(refuse(
            pool,
            account.subject(),
            "bad_password",
            attempt.origin,
            attempt.request_id,
        )
        .await);
    };
    let subject = AuditSubject {
        user: Some(account.id),
        email: Some(email),
        organization,
    };
    if !active {
        tx.rollback().await?;
        return Ok(refuse(
            pool,
            subject,
            "inactive",
            attempt.origin,
            attempt.request_id,
        )
        .await);
    }
    if totp {
        let now = Utc::now();
        let token = signing.issue_mfa(account.id, Binding::Password, now, challenge_lifetime)?;
        write_activity(
            &mut *tx,
            AuditActivity::MfaChallenge {
                method: "totp",
                delivery_failed: false,
            },
            subject,
            attempt.origin,
            attempt.request_id,
            now,
        )
        .await?;
        tx.commit().await?;
        return Ok(PasswordDecision::Totp { token });
    }
    Ok(PasswordDecision::Continue {
        user: account.id,
        verified_at,
        transaction: tx,
    })
}
