//! Complete a password challenge with an authenticator or recovery code.
use super::*;
use crate::{
    enrolled_factor::FactorDecision, login_throttle::RateLimited, mfa_challenges::Binding,
};

pub(super) async fn handle(
    State(login): State<Option<Arc<Login>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() != axum::http::Method::POST {
        let mut res = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        res.headers_mut().insert(h::ALLOW, "POST".parse().unwrap());
        return res;
    }
    let Some(login) = login else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Login signing unavailable");
    };
    let (parts, body) = req.into_parts();
    let (token, code) = match input::read(&parts.headers, body, input::factor).await {
        Ok(fields) => fields,
        Err(response) => return *response,
    };
    let origin = SessionOrigin {
        ip: client_ip(&parts.headers, peer.ip(), login.proxies),
        user_agent: header(&parts.headers, "user-agent"),
    };
    login
        .verify_factor(
            &token,
            &code,
            origin,
            header(&parts.headers, "x-request-id"),
        )
        .await
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
            )
                .into_response()
        })
}

fn subject(user: Option<Uuid>) -> AuditSubject {
    AuditSubject {
        user,
        email: None,
        organization: None,
    }
}

impl Login {
    async fn verify_factor(
        &self,
        token: &str,
        code: &str,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
    ) -> LoginResult {
        if !self.mfa_quota.allow(origin.ip) {
            return Ok(self
                .reject_factor(subject(None), "rate_limited", origin, request)
                .await);
        }
        let challenge = match self.verifier.verify(token) {
            Ok(challenge) => challenge,
            Err(error) => {
                let reason = error.audit_reason();
                return Ok(self
                    .reject_factor(subject(None), reason, origin, request)
                    .await);
            }
        };
        let user = challenge.user;
        match challenge.binding {
            Binding::Password => (),
            Binding::EmailLink(_) => {
                return Ok(self
                    .reject_factor(subject(Some(user)), "invalid_token", origin, request)
                    .await);
            }
            Binding::Passkey { .. } => {
                return Ok(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Passkey ceremony verification unavailable",
                ));
            }
        }
        let Some(verifier) = &self.factor else {
            return Ok(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Factor encryption key unavailable",
            ));
        };
        let mut tx = self.pool.begin().await?;
        let decision = verifier.consume(&mut tx, user, code, Utc::now()).await?;
        let mut actor = subject(Some(user));
        let reason = match decision {
            FactorDecision::Totp => {
                return self
                    .finish(tx, user, origin, request, LoginMethod::Totp)
                    .await;
            }
            FactorDecision::RecoveryCode => {
                return self
                    .finish(tx, user, origin, request, LoginMethod::Recovery)
                    .await;
            }
            FactorDecision::NoUser => "user_not_found",
            FactorDecision::Inactive => "inactive",
            FactorDecision::NotEnrolled => "mfa_not_enrolled",
            FactorDecision::InvalidCode => {
                (actor.email, actor.organization) =
                    sqlx::query_as("SELECT primary_email,organization_id FROM users WHERE id=$1")
                        .bind(user)
                        .fetch_one(&mut *tx)
                        .await?;
                "mfa_failed"
            }
        };
        tx.rollback().await?;
        Ok(self.reject_factor(actor, reason, origin, request).await)
    }

    async fn reject_factor(
        &self,
        subject: AuditSubject,
        reason: &'static str,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
    ) -> Response {
        if write_activity(
            &self.pool,
            AuditActivity::FactorRefused(reason),
            subject,
            origin,
            request,
            Utc::now(),
        )
        .await
        .is_err()
        {
            eprintln!("could not record MFA refusal");
        }
        match reason {
            "rate_limited" => RateLimited.into_response(),
            "mfa_failed" => problem(StatusCode::UNAUTHORIZED, "Invalid code"),
            _ => problem(StatusCode::UNAUTHORIZED, "MFA session expired"),
        }
    }
}
