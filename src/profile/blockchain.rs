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
    match state.chain_health.read(&state.blockchain).await {
        Ok(report) => Json(report).into_response(),
        Err(()) => internal(),
    }
}
