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
    let row: Option<(bool, Option<String>, bool, String)> =
        sqlx::query_as("SELECT is_admin,primary_email,is_email_verified,extra_metadata::text FROM users WHERE id=$1")
            .bind(id.user)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| Box::new(internal()))?;
    let denied = || Box::new(problem(StatusCode::FORBIDDEN, "Admin access required"));
    let (stored, email, verified, metadata) = row.ok_or_else(denied)?;
    validate_metadata(&metadata).map_err(|_| Box::new(internal()))?;
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

pub(super) fn validate_metadata(metadata: &str) -> sqlx::Result<()> {
    crate::stored_json::check_integers(metadata)?;
    admin_organizations::normalized_storage(metadata)?;
    Ok(())
}

pub(super) async fn operator(
    state: &Profile,
    headers: &HeaderMap,
) -> Result<(Transaction<'static, Postgres>, Uuid, Option<String>), Box<Response>> {
    let identity = identity(state, headers).ok_or_else(|| Box::new(unauthorized()))?;
    let (tx, email) = session(state, &identity).await?;
    Ok((tx, identity.user, email))
}

pub(super) async fn put_required() -> Response {
    let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    r.headers_mut()
        .insert(header::ALLOW, header::HeaderValue::from_static("PUT"));
    r
}

pub(super) struct UserUpdate<T> {
    pub(super) tx: Transaction<'static, Postgres>,
    pub(super) actor: Uuid,
    pub(super) email: Option<String>,
    pub(super) user: Uuid,
    pub(super) input: T,
}

pub(super) async fn user_update<T>(
    state: &Profile,
    headers: &HeaderMap,
    raw: &str,
    bytes: &[u8],
    key: &str,
    parse: impl FnOnce(Value) -> Result<T, Value>,
) -> Result<UserUpdate<T>, Box<Response>> {
    let body = crate::request_json::fields::document(headers, bytes)?;
    let (tx, actor, email) = operator(state, headers).await?;
    let body = body.ok_or_else(|| Box::new(internal()))?;
    let (user, input) = update_input::validate(raw, &body, key, parse)?;
    Ok(UserUpdate {
        tx,
        actor,
        email,
        user,
        input,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_accounts_accept_legacy_pairs_and_reject_unreadable_metadata() {
        assert!(validate_metadata(r#"[["name",3]]"#).is_ok());
        assert!(validate_metadata("false").is_ok());
        assert!(validate_metadata("true").is_err());
        assert!(validate_metadata(r#"[["name"]]"#).is_err());
    }
}
