//! Authenticate a first-party operator and resolve current administrative access.
use super::*;
use crate::login_http::problem;

pub(super) fn identity(state: &Profile, headers: &HeaderMap) -> Option<Identity> {
    let raw = credential(headers)?;
    state
        .verify
        .as_ref()?
        .read(raw)
        .filter(|id| !id.client_bound)
}

pub(super) async fn session(
    state: &Profile,
    id: &Identity,
) -> Result<(Transaction<'static, Postgres>, Option<String>), Box<Response>> {
    let mut tx = state.pool.begin().await.map_err(|_| Box::new(internal()))?;
    if state.enforce
        && revoked(&mut tx, id)
            .await
            .map_err(|_| Box::new(internal()))?
    {
        return Err(Box::new(unauthorized()));
    }
    if !state.admin_enabled {
        return Err(Box::new(problem(
            StatusCode::FORBIDDEN,
            "Admin API disabled",
        )));
    }
    let row: Option<(bool, Option<String>, bool)> =
        sqlx::query_as("SELECT is_admin,primary_email,is_email_verified FROM users WHERE id=$1")
            .bind(id.user)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| Box::new(internal()))?;
    let denied = || Box::new(problem(StatusCode::FORBIDDEN, "Admin access required"));
    let (stored, email, verified) = row.ok_or_else(denied)?;
    if !config::effective_admin(
        stored,
        email.as_deref(),
        verified,
        state.production,
        &state.admins,
    ) {
        return Err(denied());
    }
    Ok((tx, email))
}
