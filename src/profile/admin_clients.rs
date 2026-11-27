//! Administrative access to the OAuth client registry.
mod page;
use super::*;
use crate::{
    grant_response::SessionOrigin,
    login_http::problem,
    token_http::{client_ip, header as header_value},
};
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
    if method != Method::GET {
        return method_refused();
    }
    handle(
        &state,
        &headers,
        Operation::Page(query.as_deref().unwrap_or("")),
    )
    .await
}

pub(super) async fn detail(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let op = match method {
        Method::GET => Operation::Client(&id),
        Method::DELETE => Operation::Deactivate(
            &id,
            SessionOrigin {
                ip: client_ip(&headers, peer.ip(), state.proxies),
                user_agent: header_value(&headers, "user-agent"),
            },
        ),
        _ => return method_refused(),
    };
    handle(&state, &headers, op).await
}

fn method_refused() -> Response {
    let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    response
        .headers_mut()
        .insert(header::ALLOW, "GET".parse().unwrap());
    response
}
enum Operation<'a> {
    Page(&'a str),
    Client(&'a str),
    Deactivate(&'a str, SessionOrigin<'a>),
}
async fn handle(state: &Profile, headers: &HeaderMap, op: Operation<'_>) -> Response {
    let Some(id) = credential(headers)
        .and_then(|s| state.verify.as_ref()?.read(s))
        .filter(|id| !id.client_bound)
    else {
        return unauthorized();
    };
    authorized_operation(state, &id, op)
        .await
        .unwrap_or_else(|_| internal())
}
async fn authorized_operation(
    state: &Profile,
    id: &Identity,
    op: Operation<'_>,
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
    let Some((stored, email, verified)) = operator else {
        return Ok(problem(StatusCode::FORBIDDEN, "Admin access required"));
    };
    if !config::effective_admin(
        stored,
        email.as_deref(),
        verified,
        state.production,
        &state.admins,
    ) {
        return Ok(problem(StatusCode::FORBIDDEN, "Admin access required"));
    }
    match op {
        Operation::Deactivate(target, origin) => {
            deactivate(tx, id.user, email.as_deref(), target, origin).await
        }

        Operation::Client(id) => {
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
        Operation::Page(query) => match Page::parse(query) {
            Ok(page) => collection(&mut tx, page).await,
            Err(issues) => Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":issues})),
            )
                .into_response()),
        },
    }
}
async fn deactivate(
    mut tx: Transaction<'_, Postgres>,
    operator: Uuid,
    email: Option<&str>,
    target: &str,
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let updated=sqlx::query("UPDATE oauth_clients SET updated_at=CASE WHEN active THEN now() ELSE updated_at END,active=false WHERE client_id=$1").bind(target).execute(&mut *tx).await?;
    if updated.rows_affected() == 0 {
        return Ok(problem(StatusCode::NOT_FOUND, "OAuth client not found"));
    }
    crate::admin_audit::append_client_action(
        &mut tx,
        "oauth_client.delete",
        Some((operator, email)),
        target,
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
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
            json!(row.try_get::<Option<sqlx::types::Json<Option<BTreeSet<String>>>>, _>(field)?);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn sql_and_json_null_client_lists_share_the_same_response() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let row = sqlx::query("SELECT gen_random_uuid() AS id, NULL::uuid AS created_by_user_id,
            'client'::text AS client_id,'App'::text AS name,NULL::text AS description,
            'public'::text AS client_type,NULL::text AS access_token_audience,'admin'::text AS registration_source,
            'null'::jsonb AS allowed_audiences,NULL::jsonb AS redirect_uris,'[]'::jsonb AS post_logout_redirect_uris,
            false AS trusted,true AS active,now() AS created_at,now() AS updated_at,
            NULL::timestamptz AS last_used_at,''::text AS allowed_scopes,''::text AS grant_types,3600 AS max_token_ttl_s")
            .fetch_one(&pool).await.unwrap();
        let client = item(row).unwrap();
        assert_eq!(client["allowed_audiences"], Value::Null);
        assert_eq!(client["redirect_uris"], Value::Null);
        assert_eq!(client["post_logout_redirect_uris"], json!([]));
    }
}
