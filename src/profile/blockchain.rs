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
