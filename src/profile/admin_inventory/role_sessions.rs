//! Active role sessions visible to an operator through the configured provider.
use super::*;
use axum::extract::Path;

pub(in crate::profile) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let id = match crate::query::path_uuid(&raw, "role_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let sessions = if let Some(chain) = chain {
        if tx.commit().await.is_err() {
            return internal();
        }
        match chain.operator_roles().await {
            Ok(roles) => {
                let key = id.to_string();
                roles.iter().any(|r| r["id"] == key).then(Vec::new)
            }
            Err(error) => return admin_client_roles::chain_error(error),
        }
    } else {
        match postgres(&mut tx, id).await {
            Ok(sessions) => sessions,
            Err(_) => return internal(),
        }
    };
    match sessions {
        Some(rows) => response("sessions", rows),
        None => crate::login_http::problem(StatusCode::NOT_FOUND, &format!("role {id}")),
    }
}

async fn postgres(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<Vec<Value>>, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM iam_roles WHERE id=$1)")
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
    if !exists {
        return Ok(None);
    }
    let rows = sqlx::query_as::<_, (Uuid, Uuid, DateTime<Utc>, DateTime<Utc>)>(
        "SELECT id,identity_id,start_at,expiry_at FROM iam_role_sessions
         WHERE role_id=$1 AND active AND expiry_at>statement_timestamp()",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    let sessions = rows
        .into_iter()
        .map(|(session, identity, start, expiry)| {
            active_session(session, id, identity, start, expiry)
        })
        .collect();
    Ok(Some(sessions))
}

pub(super) fn active_session(
    id: Uuid,
    role: Uuid,
    identity: Uuid,
    start: DateTime<Utc>,
    expiry: DateTime<Utc>,
) -> Value {
    json!({
        "id":id,
        "role_id":role,
        "identity_id":identity,
        "start_at":timestamp(start),
        "expiry_at":timestamp(expiry),
        "active":true
    })
}

// The two role-session route templates intersect at /roles/sessions/sessions.
// For a read or an unsupported method the inventory route takes precedence.
pub(in crate::profile) async fn session_method(
    state: State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    path: Path<String>,
) -> Response {
    if path.0 == "policies" {
        return crate::token_http::post_only().await;
    }
    if path.0 == "sessions" {
        return list(state, method, headers, path).await;
    }
    delete_only().await
}

pub(in crate::profile) async fn revoke(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(record) => record,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let id = match crate::query::path_uuid(&raw, "session_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    if chain.is_some() {
        // The configured chain provider cannot resolve session UUIDs.
        return crate::login_http::problem(StatusCode::NOT_FOUND, &id.to_string());
    }
    let origin = crate::grant_response::SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    deactivate(tx, id, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn deactivate(
    mut tx: Transaction<'_, Postgres>,
    id: Uuid,
    actor: (Uuid, Option<&str>),
    origin: crate::grant_response::SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let active: Option<bool> =
        sqlx::query_scalar("SELECT active FROM iam_role_sessions WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    match active {
        None => {
            return Ok(crate::login_http::problem(
                StatusCode::NOT_FOUND,
                &format!("session {id}"),
            ));
        }
        Some(true) => {
            sqlx::query("UPDATE iam_role_sessions SET active=false WHERE id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        Some(false) => {}
    }
    removal::commit_deletion(
        tx,
        actor,
        "iam.role.session.revoke",
        ("iam_role_session", id),
        origin,
    )
    .await
}
