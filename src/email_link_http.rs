//! Inspect or decide an emailed sign-in challenge using its recipient token.
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    login_throttle::{LoginThrottle, RateLimited},
    request_json::parse_body,
    token_http::{client_ip, header},
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{ConnectInfo, Request, State},
    http::{Method, StatusCode, header as h},
    response::{IntoResponse, Response},
    routing::any,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{error::Error, net::SocketAddr, sync::Arc};
use uuid::Uuid;

#[derive(Clone, Copy)]
enum Action {
    Inspect,
    Confirm,
    Deny,
}

struct Links {
    pool: PgPool,
    quota: LoginThrottle,
    proxies: usize,
}

pub fn routes(pool: PgPool) -> Result<Router, Box<dyn Error>> {
    let state = Arc::new(Links {
        pool,
        quota: LoginThrottle::configured()?,
        proxies: crate::token_runtime::number("TRUSTED_PROXY_COUNT", 0)?.try_into()?,
    });
    let mut router = Router::new();
    for (path, action) in [
        ("inspect", Action::Inspect),
        ("confirm", Action::Confirm),
        ("deny", Action::Deny),
    ] {
        router = router.route(
            &format!("/api/v1/auth/magic-link/{path}"),
            any(handle).layer(Extension(action)),
        );
    }
    Ok(router.with_state(state))
}

fn link_token(body: Value) -> Result<String, Value> {
    crate::request_json::token_field(body, "token", 16, 128)
}

async fn handle(
    State(state): State<Arc<Links>>,
    Extension(action): Extension<Action>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        let mut res = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        res.headers_mut().insert(h::ALLOW, "POST".parse().unwrap());
        return res;
    }
    let (parts, stream) = req.into_parts();
    let Ok(bytes) = to_bytes(stream, 2 * 1024 * 1024).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let token = match parse_body(&parts.headers, &bytes).and_then(link_token) {
        Ok(t) => t,
        Err(issue) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":[issue]})),
            )
                .into_response();
        }
    };
    let ip = client_ip(&parts.headers, peer.ip(), state.proxies);
    if !state.quota.allow(ip) {
        return RateLimited.into_response();
    }
    let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
    let result = match action {
        Action::Inspect => inspect(&state.pool, &digest).await,
        _ => {
            decide(
                &state.pool,
                &digest,
                action,
                SessionOrigin {
                    ip,
                    user_agent: header(&parts.headers, "user-agent"),
                },
                header(&parts.headers, "x-request-id"),
            )
            .await
        }
    };
    result.unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
        )
            .into_response()
    })
}

fn invalid() -> Response {
    problem(StatusCode::BAD_REQUEST, "Invalid or expired link")
}

fn timestamp(time: DateTime<Utc>) -> String {
    let precision = if time.timestamp_subsec_micros() == 0 {
        SecondsFormat::Secs
    } else {
        SecondsFormat::Micros
    };
    time.to_rfc3339_opts(precision, true)
}

async fn inspect(pool: &PgPool, digest: &str) -> Result<Response, sqlx::Error> {
    type Pending = (
        String,
        DateTime<Utc>,
        DateTime<Utc>,
        Option<String>,
        Option<String>,
    );
    let row = sqlx::query_as::<_, Pending>(
        "SELECT match_code, created_at, expires_at, created_ip, created_user_agent
         FROM magic_link_challenges
         WHERE token_hash=$1 AND status='pending' AND expires_at>clock_timestamp()",
    )
    .bind(digest)
    .fetch_optional(pool)
    .await?;
    let Some((code, created_at, expires_at, ip, user_agent)) = row else {
        return Ok(invalid());
    };
    let details = json!({
        "match_code": code,
        "created_at": timestamp(created_at),
        "expires_at": timestamp(expires_at),
        "ip": ip,
        "user_agent": user_agent,
    });
    Ok(([(h::CACHE_CONTROL, "no-store")], Json(details)).into_response())
}

async fn decide(
    pool: &PgPool,
    digest: &str,
    action: Action,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let pending = sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT id, user_id FROM magic_link_challenges
         WHERE token_hash=$1 AND status='pending' AND expires_at>clock_timestamp()",
    )
    .bind(digest)
    .fetch_optional(&mut *tx)
    .await?;
    let user = pending.map(|(_, user)| user);
    let target = if matches!(action, Action::Confirm) {
        "confirmed"
    } else {
        "denied"
    };
    let changed = if let Some((id, _)) = pending {
        let update = sqlx::query(
            "UPDATE magic_link_challenges SET status=$1, decided_at=clock_timestamp()
             WHERE id=$2 AND status='pending' AND expires_at>clock_timestamp()",
        )
        .bind(target)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        update.rows_affected() == 1
    } else {
        false
    };
    let subject = AuditSubject {
        user,
        email: None,
        organization: None,
    };
    if changed && matches!(action, Action::Confirm) {
        write_activity(
            &mut *tx,
            AuditActivity::EmailDecision { reason: None },
            subject,
            origin,
            request,
            Utc::now(),
        )
        .await?;
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    tx.commit().await?;
    let reason = if changed { "denied" } else { "invalid_token" };
    if write_activity(
        pool,
        AuditActivity::EmailDecision {
            reason: Some(reason),
        },
        subject,
        origin,
        request,
        Utc::now(),
    )
    .await
    .is_err()
    {
        eprintln!("could not record email-link refusal");
    }
    Ok(if changed {
        StatusCode::NO_CONTENT.into_response()
    } else {
        invalid()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_length_counts_unicode_characters_at_both_limits() {
        for length in [15, 16, 128, 129] {
            let value = "λ".repeat(length);
            let result = link_token(json!({"token": value}));
            assert_eq!(result.is_ok(), (16..=128).contains(&length));
        }
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn only_pending_unexpired_challenges_reveal_attempt_details() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE magic_link_challenges (
                token_hash text, status text, match_code text, created_at timestamptz,
                expires_at timestamptz, created_ip text, created_user_agent text
             );
             INSERT INTO magic_link_challenges
             SELECT status, status, '45', now(), now() + interval '1 minute', NULL, NULL
             FROM unnest(ARRAY['pending','confirmed','consumed','denied']) AS t(status);
             INSERT INTO magic_link_challenges VALUES
             ('expired','pending','45',now(),now(),NULL,NULL);",
        )
        .execute(&pool)
        .await
        .unwrap();
        for _ in 0..2 {
            let response = inspect(&pool, "pending").await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[h::CACHE_CONTROL], "no-store");
        }
        for token in ["confirmed", "consumed", "denied", "expired", "unknown"] {
            let response = inspect(&pool, token).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
