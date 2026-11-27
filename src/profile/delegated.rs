//! Service-client authorization for delegated role management.
use super::*;

pub(super) async fn client(state: &Profile, headers: &HeaderMap) -> Result<String, Box<Response>> {
    use crate::{csrf::bearer, login_http::service_identity, token_revocation::VerifiedToken};
    let required = || service_identity::unauthorized("Service token required");
    let claims = bearer(headers)
        .and_then(|raw| state.verify.as_ref()?.service_claims(raw))
        .ok_or_else(required)?;
    let Ok(VerifiedToken::Service { client, id, .. }) =
        VerifiedToken::from_verified_claims(&claims)
    else {
        return Err(required());
    };
    service_identity::registration(&state.pool, &client, id, state.enforce)
        .await
        .map_err(|_| Box::new(internal()))?
        .map_err(service_identity::unauthorized)?;
    if !claims["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .any(|scope| scope == "roles:manage")
    {
        return Err(Box::new(crate::login_http::problem(
            StatusCode::FORBIDDEN,
            "Insufficient scope: roles:manage required",
        )));
    }
    Ok(client)
}
