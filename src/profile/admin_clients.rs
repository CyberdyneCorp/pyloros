//! Administrative reads of the OAuth client registry.
mod page;
use super::*;
use crate::login_http::problem;
use axum::extract::{Path, RawQuery};
use page::Page;
use sqlx::{Row, postgres::PgRow};
use std::collections::BTreeSet;

const COLUMNS: &str = "id,client_id,name,description,allowed_scopes,allowed_audiences,
    max_token_ttl_s,grant_types,client_type,redirect_uris,post_logout_redirect_uris,
    access_token_audience,trusted,registration_source,active,created_by_user_id,
    created_at,updated_at,last_used_at";

pub(super) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    read(
        &state,
        method,
        &headers,
        Read::Page(query.as_deref().unwrap_or("")),
    )
    .await
}
pub(super) async fn detail(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    read(&state, method, &headers, Read::Client(&id)).await
}
enum Read<'a> {
    Page(&'a str),
    Client(&'a str),
}
async fn read(state: &Profile, method: Method, headers: &HeaderMap, op: Read<'_>) -> Response {
    if method != Method::GET {
        let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(header::ALLOW, "GET".parse().unwrap());
        return r;
    }
    let Some(id) = credential(headers)
        .and_then(|s| state.verify.as_ref()?.read(s))
        .filter(|id| !id.client_bound)
    else {
        return unauthorized();
    };
    authorized_read(state, &id, op)
        .await
        .unwrap_or_else(|_| internal())
}
async fn authorized_read(
    state: &Profile,
    id: &Identity,
    op: Read<'_>,
) -> Result<Response, sqlx::Error> {
    let mut tx = state.pool.begin().await?;
    if state.enforce && revoked(&mut tx, id).await? {
        return Ok(unauthorized());
    }
    if !state.admin_enabled {
        return Ok(problem(StatusCode::FORBIDDEN, "Admin API disabled"));
    }
    let operator: Option<(bool, Option<String>, bool)> =
        sqlx::query_as("SELECT is_admin,primary_email,is_email_verified FROM users WHERE id=$1")
            .bind(id.user)
            .fetch_optional(&mut *tx)
            .await?;
    if !operator.is_some_and(|(stored, email, verified)| {
        config::effective_admin(
            stored,
            email.as_deref(),
            verified,
            state.production,
            &state.admins,
        )
    }) {
        return Ok(problem(StatusCode::FORBIDDEN, "Admin access required"));
    }
    match op {
        Read::Client(id) => {
            let row = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM oauth_clients WHERE client_id=$1"
            ))
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
            Ok(match row {
                Some(row) => Json(item(row)?).into_response(),
                None => problem(StatusCode::NOT_FOUND, "OAuth client not found"),
            })
        }
        Read::Page(query) => match Page::parse(query) {
            Ok(page) => collection(&mut tx, page).await,
            Err(issues) => Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":issues})),
            )
                .into_response()),
        },
    }
}
async fn collection(
    tx: &mut Transaction<'_, Postgres>,
    page: Page,
) -> Result<Response, sqlx::Error> {
    let Some(offset) = (page.number - 1)
        .checked_mul(page.size.into())
        .and_then(|n| i64::try_from(n).ok())
    else {
        return Ok(internal());
    };
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_clients WHERE NOT $1 OR active")
            .bind(page.active_only)
            .fetch_one(&mut **tx)
            .await?;
    let rows=sqlx::query(&format!("SELECT {COLUMNS} FROM oauth_clients WHERE NOT $1 OR active ORDER BY created_at DESC LIMIT $2 OFFSET $3"))
        .bind(page.active_only).bind(page.size).bind(offset).fetch_all(&mut **tx).await?;
    let clients = rows.into_iter().map(item).collect::<Result<Vec<_>, _>>()?;
    Ok(
        Json(json!({"total":total,"clients":clients,"page_size":page.size,"page":page.number}))
            .into_response(),
    )
}
fn item(row: PgRow) -> Result<Value, sqlx::Error> {
    let mut result = json!({});
    for field in ["id", "created_by_user_id"] {
        result[field] = json!(row.try_get::<Option<Uuid>, _>(field)?);
    }
    for field in [
        "client_id",
        "name",
        "description",
        "client_type",
        "access_token_audience",
        "registration_source",
    ] {
        result[field] = json!(row.try_get::<Option<String>, _>(field)?);
    }
    for field in [
        "allowed_audiences",
        "redirect_uris",
        "post_logout_redirect_uris",
    ] {
        result[field] =
            json!(row.try_get::<Option<sqlx::types::Json<BTreeSet<String>>>, _>(field)?);
    }
    for field in ["trusted", "active"] {
        result[field] = json!(row.try_get::<bool, _>(field)?);
    }
    for field in ["created_at", "updated_at", "last_used_at"] {
        result[field] = json!(
            row.try_get::<Option<DateTime<Utc>>, _>(field)?
                .map(timestamp)
        );
    }
    for field in ["allowed_scopes", "grant_types"] {
        let raw = row.try_get::<Option<String>, _>(field)?.unwrap_or_default();
        let text = if raw.is_empty() && field == "grant_types" {
            "client_credentials"
        } else {
            &raw
        };
        result[field] = json!(text.split_whitespace().collect::<BTreeSet<_>>());
    }
    result["max_token_ttl_s"] = json!(row.try_get::<i32, _>("max_token_ttl_s")?);
    Ok(result)
}
