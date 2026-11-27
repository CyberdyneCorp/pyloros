//! Read the active process-local blockchain configuration as an administrator.
use super::*;

pub(super) async fn get(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    match administrator::operator(&state, &headers).await {
        Ok(_) => Json(state.blockchain.view().await).into_response(),
        Err(response) => *response,
    }
}

pub(super) async fn health(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    if let Err(response) = administrator::operator(&state, &headers).await {
        return *response;
    }
    match state.blockchain.health().await {
        Ok(report) => Json(report).into_response(),
        Err(()) => internal(),
    }
}

mod input;
mod mnemonic;

pub(super) async fn update(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match admin_fields::body(&headers, &bytes) {
        Ok(body) => body,
        Err(r) => return *r,
    };
    let (mut tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(context) => context,
        Err(r) => return *r,
    };
    let Some(body) = body else { return internal() };
    let mut input = match input::parse(&body) {
        Ok(input) => input,
        Err(issues) => return passkeys::validation(issues),
    };
    if let Some(words) = input.mnemonic.take().filter(|s| !s.is_empty()) {
        let index = input.index;
        match crate::passwords::password_worker(move || mnemonic::derive(&words, index)).await {
            Ok(Some(key)) => input.patch.private_key = Some(key),
            Ok(None) => {
                return crate::login_http::problem(StatusCode::BAD_REQUEST, "invalid mnemonic");
            }
            Err(_) => return internal(),
        }
    }
    // Preserve the order of local changes in the audit chain across concurrent PUTs.
    let _writer = state.blockchain.admin_updates.lock().await;
    let view = state.blockchain.update(input.patch).await;
    let origin = crate::grant_response::SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    if crate::admin_audit::append(
        &mut tx,
        "settings.update",
        Some((actor, email.as_deref())),
        ("settings", "blockchain"),
        input.audit,
        origin,
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return internal();
    }
    Json(json!({"success":true,"message":"settings updated","signer_address":view.signer_address}))
        .into_response()
}
