//! Redeem an approved device grant in the same transaction as its new session.
use super::device;
use crate::{
    authorization_codes::digest,
    code_decision::{CodeDecision, OAuthError},
    grant_audit::{GrantEvent, write_event},
    grant_response::{GrantSettings, SessionOrigin},
    grant_sessions::{SessionError, SessionRecord},
    token_runtime::Runtime,
};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use std::collections::BTreeSet;
use uuid::Uuid;

pub(super) struct Request<'a> {
    pub client: &'a str,
    pub secret: Option<&'a str>,
    pub code: Option<&'a str>,
    pub resource: bool,
}

struct Refusal {
    error: OAuthError,
    reason: Option<&'static str>,
}
impl Refusal {
    fn new(
        code: &'static str,
        description: impl Into<String>,
        reason: Option<&'static str>,
    ) -> Self {
        Self {
            error: OAuthError {
                error: code,
                error_description: description.into(),
            },
            reason,
        }
    }
    fn invalid(code: &'static str, description: &str) -> Self {
        Self::new(code, description, Some(code))
    }
}

async fn poll_state(
    tx: &mut Transaction<'_, Postgres>,
    row: &PgRow,
    now: DateTime<Utc>,
) -> Result<Option<Refusal>, sqlx::Error> {
    if row.try_get::<DateTime<Utc>, _>("expires_at")? <= now {
        return Ok(Some(Refusal::new(
            "expired_token",
            "the device code has expired",
            Some("expired"),
        )));
    }
    match row.try_get::<&str, _>("status")? {
        "approved" => Ok(None),
        "denied" => Ok(Some(Refusal::new(
            "access_denied",
            "the user denied the request",
            Some("denied"),
        ))),
        "consumed" => {
            if let Some(session) = row.try_get("session_id")? {
                crate::token_revocation::revoke_session(tx, session, now).await?;
            }
            Ok(Some(Refusal::new(
                "invalid_grant",
                "device code already used",
                Some("replay_detected"),
            )))
        }
        "pending" => {
            let interval = row.try_get::<i32, _>("interval_seconds")?;
            let early = row
                .try_get::<Option<DateTime<Utc>>, _>("last_polled_at")?
                .is_some_and(|last| now - last < TimeDelta::seconds(interval.into()));
            let next = if early {
                interval.saturating_add(5)
            } else {
                interval
            };
            sqlx::query(
                "UPDATE device_authorizations SET last_polled_at=$2, interval_seconds=$3 WHERE id=$1",
            )
            .bind(row.try_get::<Uuid,_>("id")?)
            .bind(now)
            .bind(next)
            .execute(&mut **tx)
            .await?;
            let refusal = if early {
                Refusal::new(
                    "slow_down",
                    format!("poll at most every {next} seconds"),
                    None,
                )
            } else {
                Refusal::new(
                    "authorization_pending",
                    "the user has not decided yet",
                    None,
                )
            };
            Ok(Some(refusal))
        }
        _ => Err(sqlx::Error::Protocol(
            "unknown device authorization status".into(),
        )),
    }
}

struct Approved {
    id: Uuid,
    user: Uuid,
    scopes: String,
    auth_time: Option<DateTime<Utc>>,
    amr: Option<String>,
}
async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    req: &Request<'_>,
    subject: &mut Option<Uuid>,
) -> Result<Result<Approved, Refusal>, sqlx::Error> {
    let ceiling = match device::authenticated_scopes(tx, req.client, req.secret, None).await? {
        Ok(s) => s,
        Err(device::Refusal(code, description)) => {
            return Ok(Err(Refusal::new(code, description, Some(code))));
        }
    };
    let Some(code) = req.code else {
        return Ok(Err(Refusal::invalid(
            "invalid_request",
            "missing device_code",
        )));
    };
    if req.resource {
        return Ok(Err(Refusal::invalid(
            "invalid_target",
            "resource indicators are not supported for the device grant",
        )));
    }
    let row = sqlx::query(
        "SELECT id,user_id,status,expires_at,last_polled_at,interval_seconds,session_id,scopes,auth_time,amr
         FROM device_authorizations WHERE device_code_hash=$1 AND client_id=$2 FOR NO KEY UPDATE",
    )
    .bind(digest(code))
    .bind(req.client)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(Err(Refusal::invalid(
            "invalid_grant",
            "unknown device_code",
        )));
    };
    *subject = row.try_get("user_id")?;
    if let Some(refusal) = poll_state(tx, &row, Utc::now()).await? {
        return Ok(Err(refusal));
    }
    let user =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=$1 AND is_active FOR SHARE")
            .bind(*subject)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(user) = user else {
        return Ok(Err(Refusal::new(
            "invalid_grant",
            "user unavailable",
            Some("inactive"),
        )));
    };
    let available: BTreeSet<_> = ceiling.split_whitespace().collect();
    let consent: BTreeSet<_> = row
        .try_get::<&str, _>("scopes")?
        .split_whitespace()
        .collect();
    let scopes = consent
        .intersection(&available)
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    Ok(Ok(Approved {
        id: row.try_get("id")?,
        user,
        scopes,
        auth_time: row.try_get("auth_time")?,
        amr: row.try_get("amr")?,
    }))
}

pub(super) async fn exchange(
    rt: &Runtime,
    signer: &crate::grant_sessions::GrantSessionIssuer,
    req: Request<'_>,
    settings: &GrantSettings<'_>,
    origin: SessionOrigin<'_>,
    request_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<CodeDecision, SessionError> {
    let mut tx = rt.pool.begin().await?;
    let mut subject = None;
    let approved = match authorize(&mut tx, &req, &mut subject).await? {
        Ok(a) => a,
        Err(failure) => {
            tx.commit().await?;
            if let Some(reason) = failure.reason {
                let event = GrantEvent {
                    user: subject,
                    organization: None,
                    email: None,
                    reason: Some(reason),
                    client: req.client,
                    details: json!({"grant_type":"device_code"}),
                };
                if write_event(&rt.pool, event, origin, request_id, now)
                    .await
                    .is_err()
                {
                    eprintln!("could not record device poll refusal ({reason})");
                }
            }
            return Ok(CodeDecision::Refused(failure.error));
        }
    };
    let session = Uuid::new_v4();
    let record = SessionRecord {
        session,
        user: approved.user,
        client: Some(req.client),
        auth_time: approved.auth_time,
        amr: approved.amr.as_deref(),
        scopes: (!approved.scopes.is_empty()).then_some(&approved.scopes),
        resource: None,
    };
    let token = rt
        .signer
        .store_session(&mut tx, record, origin, now)
        .await?;
    let response = match signer
        .session_response(&mut tx, record, req.client, settings, now)
        .await
    {
        issued @ (Ok(_) | Err(SessionError::UnsupportedIdToken)) => issued,
        Err(error) => return Err(error),
    };
    let event = GrantEvent::issued(
        &mut tx,
        approved.user,
        req.client,
        "device_code",
        session,
        &approved.scopes,
    )
    .await?;
    signer
        .record_user_grant(&mut tx, event, origin, request_id, now)
        .await?;
    let response = response.map(|mut response| {
        response.refresh_token = approved
            .scopes
            .split_whitespace()
            .any(|v| v == "offline_access")
            .then_some(token);
        response
    });
    finish_device_grant(tx, approved.id, session, response, now).await
}

// The protocol signing refusal commits the new session but exposes no credentials.
async fn finish_device_grant(
    mut tx: Transaction<'_, Postgres>,
    id: Uuid,
    session: Uuid,
    response: Result<crate::grant_response::TokenResponse, SessionError>,
    now: DateTime<Utc>,
) -> Result<CodeDecision, SessionError> {
    let bound = match response {
        Ok(_) => Some(session),
        Err(SessionError::UnsupportedIdToken) => None,
        Err(error) => return Err(error),
    };
    sqlx::query("UPDATE device_authorizations SET status='consumed', consumed_at=$2, session_id=$3 WHERE id=$1")
        .bind(id).bind(now).bind(bound).execute(&mut *tx).await?;
    tx.commit().await?;
    response.map(CodeDecision::Issued)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn unsupported_id_token_commits_prior_writes_and_consumes_device_without_binding() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE device_authorizations(id uuid PRIMARY KEY,status text,consumed_at timestamptz,session_id uuid)")
            .execute(&mut *tx).await.unwrap();
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO device_authorizations(id,status) VALUES($1,'approved')")
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
        let now = Utc::now();
        assert!(matches!(
            finish_device_grant(
                tx,
                id,
                Uuid::new_v4(),
                Err(SessionError::UnsupportedIdToken),
                now
            )
            .await,
            Err(SessionError::UnsupportedIdToken)
        ));
        let consumed: bool = sqlx::query_scalar("SELECT status='consumed' AND consumed_at=$2 AND session_id IS NULL FROM device_authorizations WHERE id=$1")
            .bind(id).bind(now).fetch_one(&pool).await.unwrap();
        assert!(consumed);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn backoff_survives_transactions_and_expiry_precedes_approval() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let id = Uuid::new_v4();
        let now = Utc::now();
        let expiry = now + TimeDelta::minutes(1);
        sqlx::query("CREATE TEMP TABLE device_authorizations(id uuid PRIMARY KEY, status text, expires_at timestamptz, last_polled_at timestamptz, interval_seconds int)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO device_authorizations VALUES($1,'pending',$2,NULL,5)")
            .bind(id)
            .bind(expiry)
            .execute(&pool)
            .await
            .unwrap();
        for (seconds, code, interval) in [
            (0, "authorization_pending", 5),
            (1, "slow_down", 10),
            (2, "slow_down", 15),
            (18, "authorization_pending", 15),
        ] {
            let mut tx = pool.begin().await.unwrap();
            let row = sqlx::query("SELECT * FROM device_authorizations FOR NO KEY UPDATE")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            let refusal = poll_state(&mut tx, &row, now + TimeDelta::seconds(seconds))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(refusal.error.error, code);
            assert!(refusal.reason.is_none());
            tx.commit().await.unwrap();
            let stored =
                sqlx::query_scalar::<_, i32>("SELECT interval_seconds FROM device_authorizations")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(stored, interval);
        }
        let mut tx = pool.begin().await.unwrap();
        let row = sqlx::query("UPDATE device_authorizations SET status='approved' RETURNING *")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert!(poll_state(&mut tx, &row, now).await.unwrap().is_none());
        assert_eq!(
            poll_state(&mut tx, &row, expiry)
                .await
                .unwrap()
                .unwrap()
                .error
                .error,
            "expired_token"
        );
    }
}
