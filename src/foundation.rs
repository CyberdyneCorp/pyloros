//! HTTP routing shared by the public health and issuer documents.
use axum::{
    Router,
    extract::{ConnectInfo, Request},
    handler::Handler,
    http::{header, uri::Authority},
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

fn canonical_location(req: &Request, path: &str, peers: &[ipnet::IpNet]) -> String {
    let trusted = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|peer| peers.iter().any(|net| net.contains(&peer.0.ip())));
    let scheme = if trusted
        && req
            .headers()
            .get("x-forwarded-proto")
            .is_some_and(|h| h == "https")
    {
        "https"
    } else {
        req.uri().scheme_str().unwrap_or("http")
    };
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<Authority>().ok())
        .filter(|h| !h.as_str().contains('@'));
    let mut location = host.map_or_else(String::new, |h| format!("{scheme}://{h}"));
    location.push_str(path);
    if let Some(query) = req.uri().query() {
        location.push('?');
        location.push_str(query);
    }
    location
}

#[cfg(test)]
mod tests {
    use super::*;
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
