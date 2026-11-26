//! Complete a held password login from the initiating browser.
use super::*;
use crate::{
    login_throttle::RateLimited,
    mfa_challenges::{Binding, ChallengeError},
    request_json::{parse_body, token_field},
};
use axum::body::to_bytes;
use chrono::DateTime;

pub(super) async fn handle(
    State(login): State<Option<Arc<Login>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    if request.method() != axum::http::Method::POST {
        let mut res = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        res.headers_mut().insert(h::ALLOW, "POST".parse().unwrap());
        return res;
    }
    let Some(login) = login else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Login signing unavailable");
    };
    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, 2 * 1024 * 1024).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let token = match parse_body(&parts.headers, &bytes)
        .and_then(|body| token_field(body, "mfa_token", 1, 4096))
    {
        Ok(token) => token,
        Err(issue) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":[issue]})),
            )
                .into_response();
        }
    };
    let origin = SessionOrigin {
        ip: client_ip(&parts.headers, peer.ip(), login.proxies),
        user_agent: header(&parts.headers, "user-agent"),
    };
    if !login.poll_quota.allow(origin.ip) {
        return RateLimited.into_response();
    }
    login
        .poll(&token, origin, header(&parts.headers, "x-request-id"))
        .await
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
            )
                .into_response()
        })
}

impl Login {
    async fn poll(
        &self,
        token: &str,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
    ) -> LoginResult {
        let challenge = match self.verifier.verify(token) {
            Ok(value) => value,
            Err(error) => {
                let expired = matches!(error, ChallengeError::Jwt(ref e) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature));
                let reason = if expired { "expired" } else { "invalid_token" };
                return Ok(self.refuse_poll(None, reason, origin, request).await);
            }
        };
        let user = challenge.user;
        let Binding::EmailLink(id) = challenge.binding else {
            return Ok(self
                .refuse_poll(Some(user), "invalid_token", origin, request)
                .await);
        };
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as::<_, (String, DateTime<Utc>, Option<DateTime<Utc>>)>(
            "SELECT status, expires_at, decided_at FROM magic_link_challenges
             WHERE id=$1 AND user_id=$2 FOR UPDATE",
        )
        .bind(id)
        .bind(user)
        .fetch_optional(&mut *tx)
        .await?;
        let now = Utc::now();
        let confirmed = match PollState::from_row(row, now) {
            PollState::Pending => {
                return Ok((
                    StatusCode::ACCEPTED,
                    [(h::CACHE_CONTROL, "no-store")],
                    Json(json!({"status":"pending"})),
                )
                    .into_response());
            }
            PollState::Confirmed(at) => at,
            PollState::Refused(reason) => {
                tx.rollback().await?;
                return Ok(self.refuse_poll(Some(user), reason, origin, request).await);
            }
        };
        let active =
            sqlx::query_scalar::<_, bool>("SELECT is_active FROM users WHERE id=$1 FOR UPDATE")
                .bind(user)
                .fetch_optional(&mut *tx)
                .await?;
        if active != Some(true) {
            tx.rollback().await?;
            let reason = if active.is_none() {
                "user_not_found"
            } else {
                "inactive"
            };
            return Ok(self.refuse_poll(Some(user), reason, origin, request).await);
        }
        sqlx::query(
            "UPDATE magic_link_challenges SET status='consumed', decided_at=$2 WHERE id=$1",
        )
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE users SET last_magic_link_at=$2 WHERE id=$1")
            .bind(user)
            .bind(confirmed)
            .execute(&mut *tx)
            .await?;
        let mut response = self
            .finish(tx, user, origin, request, LoginMethod::Email(confirmed))
            .await?;
        if response.status().is_success() {
            response
                .headers_mut()
                .insert(h::CACHE_CONTROL, "no-store".parse()?);
        }
        Ok(response)
    }

    async fn refuse_poll(
        &self,
        user: Option<Uuid>,
        reason: &'static str,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
    ) -> Response {
        let subject = AuditSubject {
            user,
            email: None,
            organization: None,
        };
        if write_activity(
            &self.pool,
            AuditActivity::EmailLoginRefused(reason),
            subject,
            origin,
            request,
            Utc::now(),
        )
        .await
        .is_err()
        {
            eprintln!("could not record email sign-in refusal");
        }
        problem(StatusCode::BAD_REQUEST, "Sign-in was not confirmed")
    }
}

#[derive(Debug, PartialEq)]
enum PollState {
    Pending,
    Confirmed(DateTime<Utc>),
    Refused(&'static str),
}

impl PollState {
    fn from_row(
        row: Option<(String, DateTime<Utc>, Option<DateTime<Utc>>)>,
        now: DateTime<Utc>,
    ) -> Self {
        let Some((state, expires, decision)) = row else {
            return Self::Refused("invalid_token");
        };
        match state.as_str() {
            "pending" if expires > now => Self::Pending,
            "confirmed" if expires > now => Self::Confirmed(decision.unwrap_or(now)),
            "pending" => Self::Refused("expired"),
            "denied" => Self::Refused("denied"),
            "consumed" => Self::Refused("replay_detected"),
            _ => Self::Refused("invalid_token"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_expires_at_the_deadline_and_preserves_approval_time() {
        let now = Utc::now();
        let approval = now - TimeDelta::minutes(1);
        for (status, seconds, expected) in [
            ("confirmed", 1, PollState::Confirmed(approval)),
            ("confirmed", 0, PollState::Refused("invalid_token")),
            ("pending", 1, PollState::Pending),
            ("pending", 0, PollState::Refused("expired")),
            ("denied", 1, PollState::Refused("denied")),
            ("consumed", 1, PollState::Refused("replay_detected")),
        ] {
            let row = (
                status.into(),
                now + TimeDelta::seconds(seconds),
                Some(approval),
            );
            assert_eq!(PollState::from_row(Some(row), now), expected);
        }
    }
}
