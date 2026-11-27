//! Shared authentication, request decoding and validation for registry writes.
use super::*;
use crate::grant_response::SessionOrigin;

enum Kind {
    Resource,
    Origin,
}
enum Request {
    Resource(resources::write::Request),
    Origin(origins::write::Request),
}
pub(in crate::profile) async fn create_resource(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    write(Kind::Resource, &state, peer, &headers, None, &bytes).await
}

pub(in crate::profile) async fn update_resource(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    write(Kind::Resource, &state, peer, &headers, Some(&path), &bytes).await
}

pub(in crate::profile) async fn create_origin(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    write(Kind::Origin, &state, peer, &headers, None, &bytes).await
}

pub(in crate::profile) async fn update_origin(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    write(Kind::Origin, &state, peer, &headers, Some(&path), &bytes).await
}

async fn write(
    kind: Kind,
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    target: Option<&str>,
    bytes: &[u8],
) -> Response {
    let body = match admin_fields::body(headers, bytes) {
        Ok(body) => body,
        Err(r) => return *r,
    };
    let Some(identity) = administrator::identity(state, headers) else {
        return unauthorized();
    };
    let Ok(registry) = catalog(state).await else {
        return internal();
    };
    let (tx, email) = match administrator::session(state, &identity).await {
        Ok(session) => session,
        Err(r) => return *r,
    };
    let Some(body) = body else { return internal() };
    let parsed = match kind {
        Kind::Resource => resources::write::Request::parse(target, &body).map(Request::Resource),
        Kind::Origin => origins::write::Request::parse(target, &body).map(Request::Origin),
    };
    let request = match parsed {
        Ok(request) => request,
        Err(issues) => return passkeys::validation(issues),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    let actor = (identity.user, email.as_deref());
    match request {
        Request::Resource(r) => r.apply(tx, state, registry, actor, origin).await,
        Request::Origin(r) => r.apply(tx, registry, actor, origin).await,
    }
    .unwrap_or_else(|_| internal())
}
