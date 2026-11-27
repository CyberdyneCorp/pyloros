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
