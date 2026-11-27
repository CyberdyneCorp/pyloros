//! Administrative authenticator reset for account recovery.
use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    token_http::{client_ip, header as value},
};
use axum::extract::Path;

pub(super) async fn reset(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    if method != Method::DELETE {
        let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
        return r;
    }
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let user = match crate::query::path_uuid(&raw, "user_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    clear(
        tx,
        user,
        (actor, email.as_deref()),
        origin,
        value(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn clear(
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let subject = sqlx::query_as::<_, (Option<String>, Option<Uuid>, bool, bool)>(
        "SELECT primary_email,organization_id,totp_enabled,totp_secret_encrypted IS NOT NULL
         FROM users WHERE id=$1",
    )
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((email, organization, was_enabled, had_secret)) = subject else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    // Clear the enrollment fields observed on this account. An already empty
    // enrollment still gets an audit event without changing its update timestamp.
    if was_enabled || had_secret {
        sqlx::query(
            "UPDATE users SET totp_enabled=totp_enabled AND NOT $2,
            totp_secret_encrypted=CASE WHEN $3 THEN NULL ELSE totp_secret_encrypted END,
            updated_at=now() WHERE id=$1",
        )
        .bind(user)
        .bind(was_enabled)
        .bind(had_secret)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id=$1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    write_activity(
        &mut *tx,
        AuditActivity::AdminMfaReset {
            operator: actor.0,
            was_enabled,
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
        "user.reset_mfa",
        Some(actor),
        ("user", &user.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
