//! Issue a temporary role session and commit its operator audit.
use super::*;
use crate::{
    grant_response::SessionOrigin, login_http::problem, request_json::role_session_numbers,
};
use axum::{body::Bytes, extract::Path};
use chrono::Datelike;
use std::collections::HashMap;

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(path): Path<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    // Both session route templates admit the literal /roles/sessions/sessions.
    let role = match path.get("role_id") {
        Some(raw) => raw.as_str(),
        None if path.get("session_id").is_some_and(|raw| raw == "sessions") => "sessions",
        None => return delete_only().await,
    };
    let doc = match role_session_numbers::document(&headers, &body) {
        Ok(doc) => doc,
        Err(error) => return *error,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(record) => record,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let Some(doc) = doc else {
        return internal();
    };
    let (role, identity, seconds) =
        match input::assumption(&doc, crate::query::path_uuid(role, "role_id")) {
            Ok(request) => request,
            Err(error) => return *error,
        };
    if let Some(chain) = chain {
        if tx.commit().await.is_err() {
            return internal();
        }
        // The configured contract snapshot exposes no roles to assume.
        return match chain.operator_roles().await {
            Ok(_) => missing(role),
            Err(error) => admin_client_roles::chain_error(error),
        };
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    store(
        tx,
        role,
        identity,
        &seconds,
        (actor, email.as_deref()),
        origin,
    )
    .await
    .unwrap_or_else(|_| internal())
}

fn missing(role: Uuid) -> Response {
    problem(StatusCode::NOT_FOUND, &format!("role {role}"))
}

async fn store(
    mut tx: Transaction<'_, Postgres>,
    role: Uuid,
    identity: Uuid,
    seconds: &str,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let limit: Option<i32> =
        sqlx::query_scalar("SELECT max_session_duration_s FROM iam_roles WHERE id=$1")
            .bind(role)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(limit) = limit else {
        return Ok(missing(role));
    };
    let duration = seconds.parse::<i64>();
    if duration
        .as_ref()
        .map_or(!seconds.starts_with('-'), |n| *n > i64::from(limit))
    {
        return Ok(problem(
            StatusCode::BAD_REQUEST,
            &format!("{seconds}s exceeds role max {limit}s"),
        ));
    }
    let start =
        DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).expect("current UTC time");
    let Some(expiry) = duration
        .ok()
        .and_then(chrono::Duration::try_seconds)
        .and_then(|d| start.checked_add_signed(d))
        .filter(|date| (1..=9999).contains(&date.year()))
    else {
        return Ok(internal());
    };
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO iam_role_sessions (id, role_id, identity_id, start_at, expiry_at, active)
         VALUES ($1, $2, $3, $4, $5, true)",
    )
    .bind(id)
    .bind(role)
    .bind(identity)
    .bind(start)
    .bind(expiry)
    .execute(&mut *tx)
    .await?;
    crate::admin_audit::append(
        &mut tx,
        "iam.role.assume",
        Some(actor),
        ("iam_role", &role.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    let session = role_sessions::active_session(id, role, identity, start, expiry);
    Ok((StatusCode::CREATED, Json(session)).into_response())
}
