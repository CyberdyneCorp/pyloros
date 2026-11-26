//! Per-process admission control for validated password-login requests.
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    password_login::PasswordAttempt,
};
use axum::{
    Json,
    http::{StatusCode, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;
use std::{
    collections::HashMap,
    env,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(60);

struct Bucket {
    tokens: f64,
    last: f64,
}

struct Sources {
    buckets: HashMap<Option<IpAddr>, Bucket>,
    last_cleanup: Instant,
}

pub struct LoginThrottle {
    limit: u64,
    origin: Instant,
    sources: Mutex<Sources>,
}

pub struct RateLimited;

impl IntoResponse for RateLimited {
    fn into_response(self) -> Response {
        (StatusCode::TOO_MANY_REQUESTS,[(RETRY_AFTER,"60")],
         Json(json!({"type":"about:blank","status":429,"title":"Too many requests","detail":"Too many requests"}))).into_response()
    }
}

impl LoginThrottle {
    pub fn configured() -> Result<Self, std::num::ParseIntError> {
        let limit = env::var("RATELIMIT_LOGIN_PER_MIN").map_or(Ok(10), |s| s.parse())?;
        Ok(Self::new(limit))
    }

    pub fn new(limit_per_minute: i64) -> Self {
        let origin = Instant::now();
        Self {
            origin,
            limit: limit_per_minute.max(0) as u64,
            sources: Mutex::new(Sources {
                buckets: HashMap::new(),
                last_cleanup: origin,
            }),
        }
    }

    /// Call once per validated request, before credential lookup or hashing.
    pub async fn admit(
        &self,
        pool: &PgPool,
        attempt: &PasswordAttempt<'_>,
    ) -> Result<(), RateLimited> {
        if self.allow(attempt.origin.ip) {
            return Ok(());
        }
        let subject = AuditSubject {
            user: None,
            email: Some(attempt.email.into()),
            organization: None,
        };
        if write_activity(
            pool,
            AuditActivity::LoginRateLimited,
            subject,
            attempt.origin,
            attempt.request_id,
            Utc::now(),
        )
        .await
        .is_err()
        {
            eprintln!("could not record throttled password login");
        }
        Err(RateLimited)
    }

    pub(crate) fn allow(&self, ip: Option<IpAddr>) -> bool {
        self.consume(ip, Instant::now)
    }

    fn consume(&self, ip: Option<IpAddr>, clock: impl FnOnce() -> Instant) -> bool {
        if self.limit == 0 {
            return true;
        }
        let mut sources = self.sources.lock().expect("login quota lock");
        let now = clock();
        let seconds = now.duration_since(self.origin).as_secs_f64();
        if now.duration_since(sources.last_cleanup) >= WINDOW {
            sources
                .buckets
                .retain(|_, bucket| seconds - bucket.last < WINDOW.as_secs_f64());
            sources.last_cleanup = now;
        }
        let capacity = self.limit as f64;
        let bucket = sources.buckets.entry(ip).or_insert(Bucket {
            tokens: capacity,
            last: seconds,
        });
        let elapsed = seconds - bucket.last;
        bucket.tokens = (bucket.tokens + elapsed * (capacity / WINDOW.as_secs_f64())).min(capacity);
        bucket.last = seconds;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractional_refill_preserves_independent_quotas() {
        let limiter = LoginThrottle::new(2);
        let start = limiter.origin;
        let check = |ip, ms| limiter.consume(ip, || start + Duration::from_millis(ms));
        assert!(check(None, 0));
        assert!(check(None, 0));
        assert!(!check(None, 0));
        assert!(check(Some("127.0.0.1".parse().unwrap()), 0));
        assert!(!check(None, 29999));
        assert!(!check(None, 30000));
        assert!(check(None, 30001));
        assert!(!check(None, 30001));
        assert!(check(None, 90001));
        assert!(check(None, 90001));
        assert!(!check(None, 90001));
        assert_eq!(limiter.sources.lock().unwrap().buckets.len(), 1);
        let disabled = LoginThrottle::new(-1);
        assert!((0..20).all(|_| disabled.consume(None, Instant::now)));
    }

    #[test]
    fn simultaneous_attempts_share_the_available_tokens() {
        let limiter = LoginThrottle::new(4);
        let start = limiter.origin;
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..16)
                .map(|_| s.spawn(|| limiter.consume(None, || start)))
                .collect();
            assert_eq!(
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .filter(|accepted| *accepted)
                    .count(),
                4
            );
        });
    }
}
