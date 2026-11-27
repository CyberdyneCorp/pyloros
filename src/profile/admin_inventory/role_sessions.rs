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
            json!({
                "id":session, "role_id":id,"identity_id":identity,"active":true,
                "start_at":timestamp(start),"expiry_at":timestamp(expiry)
            })
        })
        .collect();
    Ok(Some(sessions))
}
