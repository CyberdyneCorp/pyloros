//! Account-wide credential metadata for the administrative user detail screen.
use super::*;
use axum::extract::Path;
use sqlx::Row;

#[derive(Serialize)]
struct AdminRecord {
    rp_id: String,
    #[serde(flatten)]
    key: Record,
}

pub(in crate::profile) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let (mut tx, user) = match admin_users::target(&state, &method, &headers, &raw).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    inventory(&mut tx, user)
        .await
        .unwrap_or_else(|_| internal())
}

async fn inventory(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Response, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)")
        .bind(user)
        .fetch_one(&mut **tx)
        .await?;
    if !exists {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    }
    let keys = sqlx::query(
        "SELECT id,rp_id,name,created_at,last_used_at,backup_eligible,backed_up FROM passkeys
         WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(user)
    .try_map(|row| {
        Ok(AdminRecord {
            rp_id: row.try_get("rp_id")?,
            key: record(row)?,
        })
    })
    .fetch_all(&mut **tx)
    .await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(keys)).into_response())
}
