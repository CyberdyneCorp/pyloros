//! Virtual product inventory for the storefront product picker.
use super::*;
use sqlx::Row;

pub(super) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if method != Method::GET {
        return passkeys::post_required();
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(error) => return *error,
    };
    let params =
        url::form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes()).collect();
    let mut issues = Vec::new();
    let (page, size) = crate::query::pagination(&params, 50, 200, &mut issues);
    let active = crate::query::active_only(params.get("active_only").map(|s| s.as_ref()))
        .unwrap_or_else(|error| {
            issues.push(error);
            false
        });
    if !issues.is_empty() {
        return passkeys::validation(issues);
    }
    inventory(&mut tx, page, size, active)
        .await
        .unwrap_or_else(|_| internal())
}

async fn inventory(
    tx: &mut Transaction<'_, Postgres>,
    page: i128,
    size: i64,
    active: bool,
) -> sqlx::Result<Response> {
    let Some(offset) = (page - 1)
        .checked_mul(size.into())
        .and_then(|n| i64::try_from(n).ok())
    else {
        return Ok(internal());
    };
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM products WHERE NOT $1 OR active")
        .bind(active)
        .fetch_one(&mut **tx)
        .await?;
    let rows=sqlx::query("SELECT key,name,description,active,created_at,updated_at FROM products WHERE NOT $1 OR active ORDER BY key LIMIT $2 OFFSET $3").bind(active).bind(size).bind(offset).fetch_all(&mut **tx).await?;
    let products = rows.iter().map(item).collect::<sqlx::Result<Vec<_>>>()?;
    Ok(
        Json(json!({"products":products,"page":page,"page_size":size,"total":total}))
            .into_response(),
    )
}

pub(super) fn item(row: &sqlx::postgres::PgRow) -> sqlx::Result<Value> {
    Ok(json!({
        "key":row.try_get::<String,_>("key")?, "name":row.try_get::<String,_>("name")?,
        "description":row.try_get::<Option<String>,_>("description")?, "active":row.try_get::<bool,_>("active")?,
        "created_at":timestamp(row.try_get("created_at")?), "updated_at":timestamp(row.try_get("updated_at")?)
    }))
}
