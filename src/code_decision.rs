//! Commit an authorization-code exchange before exposing the decision to the transport.
use crate::{
    authorization_codes::digest,
    code_exchange::{Exchange, ExchangeRequest, Refusal, redeem_with_subject},
    grant_audit::{GrantEvent, write_event},
    grant_response::{GrantSettings, SessionOrigin, TokenResponse},
    grant_sessions::{GrantSessionIssuer, SessionError},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Serialize)]
pub struct OAuthError {
    pub error: &'static str,
    pub error_description: String,
}

impl OAuthError {
    pub fn status(&self) -> u16 {
        if self.error == "invalid_client" {
            401
        } else {
            400
        }
    }
}

impl Refusal {
    fn report(&self) -> (OAuthError, &'static str) {
        use Refusal::*;
        let (error, description) = match self {
            MissingClient => ("invalid_client", "missing client_id"),
            UnknownClient => ("invalid_client", "unknown client"),
            BadClientSecret => ("invalid_client", "bad client secret"),
            UnauthorizedClient => (
                "unauthorized_client",
                "client may not use the authorization_code grant",
            ),
            MissingCode => ("invalid_grant", "missing authorization code"),
            MissingVerifier => ("invalid_request", "missing PKCE code_verifier"),
            UnknownCode => ("invalid_grant", "unknown authorization code"),
            Replayed => ("invalid_grant", "authorization code already used"),
            Expired => ("invalid_grant", "authorization code expired"),
            RedirectMismatch => ("invalid_grant", "redirect_uri mismatch"),
            InvalidTarget => (
                "invalid_target",
                "resource does not match the authorization grant",
            ),
            InvalidProof => ("invalid_grant", "PKCE verification failed"),
            UserUnavailable => ("invalid_grant", "user unavailable"),
            ResourceRemoved => (
                "invalid_grant",
                "the grant's resource is no longer available",
            ),
        };
        let reason = match self {
            Expired => "expired",
            Replayed => "replay_detected",
            UserUnavailable => "inactive",
            _ => error,
        };
        (
            OAuthError {
                error,
                error_description: description.into(),
            },
            reason,
        )
    }
}

pub enum CodeDecision {
    Issued(TokenResponse),
    Refused(OAuthError),
}

impl GrantSessionIssuer {
    pub async fn exchange_code(
        &self,
        pool: &PgPool,
        req: &ExchangeRequest<'_>,
        settings: &GrantSettings<'_>,
        origin: SessionOrigin<'_>,
        request_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<CodeDecision, SessionError> {
        let mut tx = pool.begin().await?;
        let mut subject = None;
        let session = Uuid::new_v4();
        let refusal = match redeem_with_subject(&mut tx, req, session, now, &mut subject).await? {
            Exchange::Refused(reason) => reason,
            Exchange::Granted(claimed) => match self
                .issue_code_response(&mut tx, &claimed, settings, origin, request_id, now)
                .await
            {
                Ok(response) => {
                    tx.commit().await?;
                    return Ok(CodeDecision::Issued(response));
                }
                Err(err @ (SessionError::UnknownResource | SessionError::UnsupportedIdToken)) => {
                    sqlx::query("UPDATE oidc_authorization_codes SET session_id=NULL WHERE code_hash=$1 AND session_id=$2")
                        .bind(digest(req.code)).bind(session).execute(&mut *tx).await?;
                    if matches!(err, SessionError::UnsupportedIdToken) {
                        tx.commit().await?;
                        return Err(err);
                    }
                    Refusal::ResourceRemoved
                }
                Err(err) => return Err(err),
            },
        };
        tx.commit().await?;
        let (error, reason) = refusal.report();
        let event = GrantEvent {
            user: subject,
            email: None,
            organization: None,
            client: req.client_id,
            reason: Some(reason),
            details: json!({"grant_type":"authorization_code"}),
        };
        if write_event(pool, event, origin, request_id, now)
            .await
            .is_err()
        {
            eprintln!("could not persist token grant refusal ({reason})");
        }
        Ok(CodeDecision::Refused(error))
    }
}
