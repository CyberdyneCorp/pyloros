use axum::{
    Router,
    extract::Request,
    http::HeaderValue,
    middleware::{self, Next},
    response::Response,
};
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;

#[derive(Clone)]
pub(crate) struct UnhandledError;

pub(crate) fn unhandled_error() -> Response {
    use axum::{
        Extension,
        http::{StatusCode, header},
        response::IntoResponse,
    };
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Extension(UnhandledError),
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"type":"about:blank","title":"Internal Server Error","status":500}"#,
    )
        .into_response()
}

const POLICIES: &[(&str, &str)] = &[
    (
        "permissions-policy",
        "geolocation=(), microphone=(), camera=()",
    ),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
];

pub fn apply(router: Router, secure_transport: bool) -> Router {
    router.layer(middleware::from_fn(
        move |request: Request, next: Next| async move {
            let Ok(mut response) = AssertUnwindSafe(next.run(request)).catch_unwind().await else {
                return unhandled_error();
            };
            if response.extensions().get::<UnhandledError>().is_some() {
                return response;
            }
            let headers = response.headers_mut();
            for &(name, value) in POLICIES {
                headers.insert(name, HeaderValue::from_static(value));
            }
            headers
                .entry("content-security-policy")
                .or_insert(HeaderValue::from_static(
                    "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
                ));
            if secure_transport {
                headers.insert(
                    "strict-transport-security",
                    HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
                );
            }
            response
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use tower::ServiceExt;

    async fn unexpected_panic() -> StatusCode {
        panic!("test handler failure")
    }

    #[tokio::test]
    async fn unhandled_failure_preserves_the_generic_wire_document() {
        let response = unhandled_error();
        assert_eq!(response.headers()["content-type"], "application/json");
        let body = axum::body::to_bytes(response.into_body(), 256)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"type":"about:blank","title":"Internal Server Error","status":500}"#
        );
    }

    #[tokio::test]
    async fn only_unhandled_errors_bypass_browser_cors_and_transport_policy() {
        let origin = "https://console.example";
        let (_, origins) = tokio::sync::watch::channel([origin.to_owned()].into_iter().collect());
        let routes = Router::new()
            .route("/unhandled", get(|| async { unhandled_error() }))
            .route("/panic", get(unexpected_panic))
            .route(
                "/handled",
                get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            );
        let routes = crate::cors::apply_origins(routes, origins).unwrap();
        for secure in [false, true] {
            let app = apply(routes.clone(), secure);
            for (path, handled) in [("/unhandled", false), ("/panic", false), ("/handled", true)] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::get(path)
                            .header("origin", origin)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
                let headers = response.headers();
                for name in [
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                    "referrer-policy",
                    "permissions-policy",
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                    "access-control-expose-headers",
                    "vary",
                ] {
                    assert_eq!(headers.contains_key(name), handled, "{path} {name}");
                }
                assert_eq!(
                    headers.contains_key("strict-transport-security"),
                    handled && secure
                );
            }
        }
    }
}
