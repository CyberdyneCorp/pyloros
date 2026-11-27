//! Administrative account recovery with password replacement and session revocation.
use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    token_http::{client_ip, header as value},
};
use axum::extract::Path;

pub(super) async fn wrong_method() -> Response {
    let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    r.headers_mut()
        .insert(header::ALLOW, header::HeaderValue::from_static("PUT"));
    r
}

pub(super) async fn reset(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match admin_fields::body(&headers, &bytes) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(body) = body else {
        return internal();
    };
    let user = crate::query::path_uuid(&raw, "user_id");
    let password = password_change::password_field(body, "new_password");
    let (user, password) = match (user, password) {
        (Ok(id), Ok(pw)) => (id, pw),
        (id, pw) => {
            return password_change::invalid([id.err(), pw.err()].into_iter().flatten().collect());
        }
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    replace(
        tx,
        &state,
        (user, password),
        (actor, email.as_deref()),
        origin,
        value(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn replace(
    mut tx: Transaction<'_, Postgres>,
    state: &Profile,
    (user, password): (Uuid, String),
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, Box<dyn Error + Send + Sync>> {
    let subject = sqlx::query_as::<_, (Option<String>, Option<Uuid>)>(
        "SELECT primary_email,organization_id FROM users WHERE id=$1",
    )
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((email, organization)) = subject else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    let now = Utc::now();
    let hash = state.scheme.hash(password).await?;
    let updated = sqlx::query(
        "UPDATE users SET password_hash=$2,tokens_valid_after=$3,updated_at=now() WHERE id=$1",
    )
    .bind(user)
    .bind(hash)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Ok(internal());
    }
    let sessions = logout_all::revoke_sessions(&mut tx, user, now).await?;
    write_activity(
        &mut *tx,
        AuditActivity::AdminPasswordReset {
            operator: actor.0,
            sessions,
        },
        AuditSubject {
            user: Some(user),
            email,
            organization,
        },
        origin,
        request,
        Utc::now(),
    )
    .await?;
    crate::admin_audit::append(
        &mut tx,
        "user.reset_password",
        Some(actor),
        ("user", &user.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"user_id":user,"message":"Password reset successfully","sessions_revoked":true}),
    )
    .into_response())
}
