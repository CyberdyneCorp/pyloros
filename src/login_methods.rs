//! Public metadata consumed by the shared sign-in page.
use axum::{
    Json, Router,
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::{MethodRouter, any},
};
use serde_json::{Value, json};
use std::{env, error::Error};
use url::Url;

fn provider_configured(id: &str, secret: &str) -> bool {
    env::var(id).is_ok_and(|v| !v.is_empty()) && env::var_os(secret).is_some()
}

fn valid_host(rp: &str, dev: bool) -> bool {
    let label = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    };
    rp.len() <= 253
        && (rp.contains('.') || (dev && rp == "localhost"))
        && rp.split(['.', '-']).all(label)
}

fn valid_web_origin(origin: &str, rp: &str, dev: bool) -> bool {
    let Some((_, authority)) = origin.split_once("://") else {
        return false;
    };
    if authority.contains(['/', '?', '#', '@', '\\']) {
        return false;
    }
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let local = dev && rp == "localhost" && host == "localhost";
    (url.scheme() == "https" || (local && url.scheme() == "http"))
        && (host == rp
            || host
                .strip_suffix(rp)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

fn valid_native_origin(origin: &str, rp: &str, dev: bool) -> bool {
    match origin.strip_prefix("android:apk-key-hash:") {
        Some(hash) => {
            hash.len() == 43
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        }
        None => valid_web_origin(origin, rp, dev),
    }
}

fn configured_origins(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn passkey_rp(dev: bool) -> Result<Option<String>, Box<dyn Error>> {
    if !crate::config::flag("PASSKEYS_ENABLED")? {
        return Ok(None);
    }
    let rp = env::var("PASSKEYS_RP_ID")?;
    let origins = configured_origins("PASSKEYS_ORIGINS");
    if !valid_host(&rp, dev)
        || origins.is_empty()
        || env::var("PASSKEYS_RP_NAME").is_ok_and(|v| v.trim().is_empty())
    {
        return Err("enabled passkeys require a valid RP ID, RP name and browser origins".into());
    }
    if !origins.iter().all(|o| valid_web_origin(o, &rp, dev))
        || !configured_origins("PASSKEYS_NATIVE_ORIGINS")
            .iter()
            .all(|o| valid_native_origin(o, &rp, dev))
    {
        return Err("invalid passkey origin for this relying party".into());
    }
    Ok(Some(rp))
}

fn document_route(status: StatusCode, document: Value) -> MethodRouter {
    any(move |method: Method| async move {
        if method == Method::GET {
            return (status, Json(document)).into_response();
        }
        let problem = json!({
            "type": "about:blank", "title": "Method Not Allowed",
            "status": 405, "detail": "Method Not Allowed"
        });
        (
            StatusCode::METHOD_NOT_ALLOWED,
            [("allow", "GET")],
            Json(problem),
        )
            .into_response()
    })
}

pub fn routes(environment: &str) -> Result<Router, Box<dyn Error>> {
    let stub = crate::config::flag("OAUTH_STUB_ENABLED")?;
    let forbidden = stub && environment == "production";
    let mut providers = Vec::new();
    if stub || provider_configured("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET") {
        providers.push("google")
    }
    if stub || provider_configured("MS_CLIENT_ID", "MS_CLIENT_SECRET") {
        providers.push("microsoft")
    }
    let rp = passkey_rp(environment == "dev")?;
    let capabilities = json!({"enabled": rp.is_some(), "rp_id": rp});
    let (status, providers) = if forbidden {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({
                "type": "about:blank", "title": "Internal Server Error", "status": 500
            }),
        )
    } else {
        (StatusCode::OK, json!({"providers": providers}))
    };
    Ok(Router::new()
        .route(
            "/api/v1/auth/oauth/providers",
            document_route(status, providers),
        )
        .route(
            "/api/v1/auth/passkeys/capabilities",
            document_route(StatusCode::OK, capabilities),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn metadata_is_get_only() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let app = Router::new().route(
            "/methods",
            document_route(StatusCode::OK, json!({"providers":[]})),
        );
        for method in [Method::HEAD, Method::POST, Method::OPTIONS] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri("/methods")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()["allow"], "GET");
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            if method == Method::HEAD {
                assert!(bytes.is_empty());
            } else {
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes).unwrap()["detail"],
                    "Method Not Allowed"
                );
            }
        }
    }

    #[test]
    fn browser_origins_are_scoped_to_the_rp() {
        assert!(valid_web_origin(
            "https://admin.example.org:443",
            "example.org",
            false
        ));
        assert!(valid_web_origin("http://localhost:3001", "localhost", true));
        for invalid in [
            "https://badexample.org",
            "https://example.org/",
            "https://example.org@evil.test",
            "http://admin.example.org",
        ] {
            assert!(!valid_web_origin(invalid, "example.org", false));
        }
        assert!(!valid_host("localhost", false));
        assert!(!valid_host("example..org", true));
    }
}
