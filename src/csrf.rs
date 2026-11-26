//! Origin and double-submit checks for browser session writes.
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::watch;

pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    let (scheme, value) = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !value.is_empty()).then_some(value)
}

pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .filter(|(key, _)| *key == name)
        .map(|(_, value)| value.trim_matches('"'))
        .next_back()
}

#[derive(Clone)]
pub(crate) struct Policy {
    origins: watch::Receiver<BTreeSet<String>>,
    cookie_name: Arc<str>,
}

impl Policy {
    pub(crate) fn new(origins: watch::Receiver<BTreeSet<String>>, cookie_name: String) -> Self {
        Self {
            origins,
            cookie_name: cookie_name.into(),
        }
    }

    fn accepted_origin(&self, req: &Request) -> bool {
        let Some(value) = req.headers().get(header::ORIGIN) else {
            return true;
        };
        let Ok(origin) = value.to_str() else {
            return false;
        };
        if self.origins.borrow().contains(origin) {
            return true;
        }
        let uri = req.uri();
        let authority = uri
            .authority()
            .map(|host| host.as_str())
            .or_else(|| req.headers().get(header::HOST)?.to_str().ok());
        let scheme = uri.scheme_str().unwrap_or("http");
        authority.is_some_and(|host| origin == format!("{scheme}://{host}"))
    }

    fn refusal(&self, req: &Request) -> Option<&'static str> {
        let writes = matches!(
            *req.method(),
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        );
        let headers = req.headers();
        if !writes
            || cookie(headers, "access_token").is_none()
            || bearer(headers).is_some()
            || req.uri().path() == "/api/v1/auth/oauth2/token"
        {
            return None;
        }
        if !self.accepted_origin(req) {
            return Some("Origin not allowed");
        }
        let value = cookie(headers, &self.cookie_name).filter(|v| !v.is_empty());
        let supplied = headers.get("x-csrf-token");
        if value
            .zip(supplied)
            .is_some_and(|(token, header)| bool::from(token.as_bytes().ct_eq(header.as_bytes())))
        {
            return None;
        }
        Some("CSRF token missing or invalid")
    }
}

pub(crate) async fn check(State(policy): State<Policy>, req: Request, next: Next) -> Response {
    match policy.refusal(&req) {
        Some(title) => (
            StatusCode::FORBIDDEN,
            Json(json!({"title":title,"status":403})),
        )
            .into_response(),
        None => next.run(req).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn request(path: &str, origin: &str, supplied: &str) -> Request {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::HOST, "api.example.test")
            .header(header::ORIGIN, origin)
            .header(header::COOKIE, "access_token=session; csrf=token")
            .header("x-csrf-token", supplied)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn browser_writes_follow_current_registry_and_cookie() {
        let (updates, origins) = watch::channel(BTreeSet::new());
        let policy = Policy::new(origins, "csrf".into());
        let origin = "https://dashboard.example.test";
        let req = request("/api/v1/users/me", origin, "token");
        assert_eq!(policy.refusal(&req), Some("Origin not allowed"));
        updates.send_replace([origin.into()].into());
        assert_eq!(policy.refusal(&req), None);
        assert_eq!(
            policy.refusal(&request("/api/v1/users/me", origin, "incorrect")),
            Some("CSRF token missing or invalid")
        );
        updates.send_replace(BTreeSet::new());
        assert_eq!(policy.refusal(&req), Some("Origin not allowed"));
    }

    #[test]
    fn token_exchange_exception_matches_one_path() {
        let policy = Policy::new(watch::channel(BTreeSet::new()).1, "csrf".into());
        let origin = "http://api.example.test";
        assert_eq!(
            policy.refusal(&request("/api/v1/auth/oauth2/token", origin, "")),
            None
        );
        assert_eq!(
            policy.refusal(&request("/api/v1/auth/oauth2/token/other", origin, "")),
            Some("CSRF token missing or invalid")
        );
    }
}
