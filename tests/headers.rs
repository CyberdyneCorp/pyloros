use axum::{Router, body::Body, http::Request, routing::get};
use tower::ServiceExt;

#[tokio::test]
async fn common_policies_cover_success_and_error_responses() {
    for secure in [true, false] {
        let routes = Router::new()
            .route("/ok", get(|| async { "ok" }))
            .merge(pyloros::discovery::routes(None));
        let app = pyloros::headers::apply(routes, secure);
        for (path, status) in [("/ok", 200), ("/.well-known/jwks.json", 404)] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
            let headers = response.headers();
            assert_eq!(headers["x-frame-options"], "DENY");
            assert_eq!(headers["x-content-type-options"], "nosniff");
            assert_eq!(
                headers["referrer-policy"],
                "strict-origin-when-cross-origin"
            );
            assert_eq!(
                headers["permissions-policy"],
                "geolocation=(), microphone=(), camera=()"
            );
            assert_eq!(
                headers["content-security-policy"],
                "default-src 'self'; frame-ancestors 'none'; object-src 'none'"
            );
            assert_eq!(
                headers
                    .get("strict-transport-security")
                    .map(|v| v.to_str().unwrap()),
                secure.then_some("max-age=31536000; includeSubDomains; preload")
            );
        }
    }
}
