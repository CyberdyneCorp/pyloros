//! HTTP routing shared by the public health and issuer documents.
use axum::{
    Router,
    extract::{ConnectInfo, FromRequestParts, Request},
    handler::Handler,
    http::{Extensions, HeaderMap, Uri, header, request::Parts, uri::Authority},
    response::Redirect,
    routing::{any, get},
};
use std::net::SocketAddr;

pub(crate) fn get_resource<H, T, S>(path: &'static str, handler: H) -> Router<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    let peers = crate::config::forwarded_peers();
    let reject = crate::browser_http::method_not_allowed;
    Router::new()
        .route(path, get(handler).head(reject).fallback(reject))
        .route(
            &format!("{path}/"),
            any(move |req: Request| {
                let location = canonical_location(&req, path, &peers);
                async move { Redirect::temporary(&location) }
            }),
        )
}

/// Check alternate paths against the application's routes without running their handlers.
pub(crate) fn canonical_paths(router: Router) -> Router {
    use axum::{http::StatusCode, middleware, response::IntoResponse};
    use tower::ServiceExt;

    let paths = router.clone().route_layer(middleware::from_fn(
        |_: Request, _: middleware::Next| async { StatusCode::NO_CONTENT },
    ));
    let peers = crate::config::forwarded_peers();
    router.fallback(move |req: Request| {
        let paths = paths.clone();
        let peers = peers.clone();
        async move {
            let path = req.uri().path();
            let canonical = path.trim_end_matches('/');
            if canonical.is_empty() || canonical == path {
                return missing_route();
            }
            let probe = Request::builder()
                .uri(canonical)
                .body(axum::body::Body::empty())
                .expect("path from parsed URI");
            let matched = paths.oneshot(probe).await.expect("infallible router");
            if matched.status() != StatusCode::NO_CONTENT {
                return missing_route();
            }
            Redirect::temporary(&canonical_location(&req, canonical, &peers)).into_response()
        }
    })
}

fn missing_route() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"type":"about:blank","title":"Not Found","status":404,"detail":"Not Found"}"#,
    )
        .into_response()
}

fn canonical_location(req: &Request, path: &str, peers: &[ipnet::IpNet]) -> String {
    let mut location =
        origin(req.headers(), req.uri(), req.extensions(), peers).unwrap_or_default();
    location.push_str(path);
    if let Some(query) = req.uri().query() {
        location.push('?');
        location.push_str(query);
    }
    location
}

pub(crate) struct RequestOrigin(pub Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for RequestOrigin {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        static PEERS: std::sync::LazyLock<Vec<ipnet::IpNet>> =
            std::sync::LazyLock::new(crate::config::forwarded_peers);
        Ok(Self(origin(
            &parts.headers,
            &parts.uri,
            &parts.extensions,
            &PEERS,
        )))
    }
}

fn origin(
    headers: &HeaderMap,
    uri: &Uri,
    extensions: &Extensions,
    peers: &[ipnet::IpNet],
) -> Option<String> {
    let trusted = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|peer| peers.iter().any(|net| net.contains(&peer.0.ip())));
    let scheme = if trusted
        && headers
            .get("x-forwarded-proto")
            .is_some_and(|h| h == "https")
    {
        "https"
    } else {
        uri.scheme_str().unwrap_or("http")
    };
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<Authority>().ok());
    let authority = host
        .or_else(|| uri.authority().cloned())
        .filter(|h| !h.as_str().contains('@'))
        .map(|h| h.to_string())
        .or_else(|| extensions.get::<SocketAddr>().map(ToString::to_string));
    authority.map(|host| format!("{scheme}://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn redirect_lookup_preserves_the_query_and_never_executes_a_write() {
        use axum::{body::Body, http::StatusCode, routing::post};
        use tower::ServiceExt;
        async fn mutation() -> StatusCode {
            panic!("route lookup executed a mutation")
        }
        let routes = Router::new().route("/products/{id}", post(mutation));
        let app = canonical_paths(routes);
        for method in ["GET", "POST", "DELETE"] {
            let request = Request::builder()
                .method(method)
                .uri("/products/item///?q=a%20b")
                .header("host", "auth.example")
                .body(Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
            assert_eq!(
                response.headers()["location"],
                "http://auth.example/products/item?q=a%20b"
            );
        }
        let unknown = Request::builder()
            .uri("/unknown/")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(unknown).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn unknown_paths_return_the_not_found_document() {
        use axum::{
            body::{Body, to_bytes},
            http::StatusCode,
        };
        use tower::ServiceExt;
        let app = canonical_paths(Router::new().route("/known", get(|| async {})));
        for path in ["/", "/unknown", "/unknown/"] {
            for method in ["GET", "HEAD"] {
                let request = Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap();
                let response = app.clone().oneshot(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
                assert_eq!(response.headers()["content-type"], "application/json");
                let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
                if method == "HEAD" {
                    assert!(bytes.is_empty());
                } else {
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                        serde_json::json!({"type":"about:blank","status":404,"title":"Not Found","detail":"Not Found"})
                    );
                }
            }
        }
    }

    #[test]
    fn only_trusted_peers_supply_the_redirect_scheme() {
        let peers = ["127.0.0.1/32".parse().unwrap()];
        for (peer, scheme) in [("127.0.0.1:42", "https"), ("192.0.2.1:42", "http")] {
            let req = Request::builder()
                .uri("/health/")
                .header("host", "auth.example")
                .header("x-forwarded-proto", "https")
                .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()))
                .body(axum::body::Body::empty())
                .unwrap();
            assert_eq!(
                canonical_location(&req, "/health", &peers),
                format!("{scheme}://auth.example/health")
            );
        }
    }
}
