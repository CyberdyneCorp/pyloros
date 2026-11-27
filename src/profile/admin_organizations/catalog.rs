//! Paginated directory used by organization pickers and operators.
use super::*;
use axum::extract::RawQuery;
use std::collections::HashMap;

struct Filters {
    page: i128,
    size: i64,
    active: Option<bool>,
    github: Option<bool>,
    domain: Option<bool>,
    search: Option<String>,
}

impl Filters {
    fn parse(query: &str) -> Result<Self, Vec<Value>> {
        let fields: HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes()).collect();
        let mut issues = Vec::new();
        let (page, size) = crate::query::pagination(&fields, 50, 200, &mut issues);
        let mut flag = |name| {
            fields.get(name).and_then(|v| {
                crate::query::boolean(name, v)
                    .map_err(|e| issues.push(e))
                    .ok()
            })
        };
        let filters = Self {
            page,
            size,
            active: flag("is_active"),
            github: flag("has_github_login"),
            domain: flag("has_domain"),
            search: fields
                .get("search")
                .filter(|v| !v.is_empty())
                .map(|v| v.to_lowercase()),
        };
        if issues.is_empty() {
            Ok(filters)
        } else {
            Err(issues)
        }
    }
}

pub(in crate::profile) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if method != Method::GET {
        let mut response =
            crate::login_http::problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("POST"));
        return response;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let filters = match Filters::parse(query.as_deref().unwrap_or_default()) {
        Ok(filters) => filters,
        Err(issues) => return passkeys::validation(issues),
    };
    collection(&mut tx, filters)
        .await
        .unwrap_or_else(|_| internal())
}

const FILTER: &str = "FROM organizations o
    WHERE ($1::boolean IS NULL OR o.is_active=$1)
    AND ($2::boolean IS NULL OR (o.github_login IS NOT NULL)=$2)
    AND ($3::boolean IS NULL OR (o.domain_name IS NOT NULL)=$3)
    AND ($4::text IS NULL OR strpos(lower(o.name),$4)>0 OR strpos(lower(o.short_name),$4)>0
         OR strpos(lower(o.domain_name),$4)>0 OR strpos(lower(o.github_login),$4)>0)";

async fn collection(
    tx: &mut Transaction<'_, Postgres>,
    filters: Filters,
) -> Result<Response, sqlx::Error> {
    let Some(offset) = (filters.page - 1)
        .checked_mul(filters.size.into())
        .and_then(|n| i64::try_from(n).ok())
    else {
        return Ok(internal());
    };
    let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) {FILTER}"))
        .bind(filters.active)
        .bind(filters.github)
        .bind(filters.domain)
        .bind(&filters.search)
        .fetch_one(&mut **tx)
        .await?;
    let rows = sqlx::query_as::<_, DirectoryRow>(&format!(
        "SELECT {COLUMNS} {FILTER} ORDER BY o.name LIMIT $5 OFFSET $6"
    ))
    .bind(filters.active)
    .bind(filters.github)
    .bind(filters.domain)
    .bind(&filters.search)
    .bind(filters.size)
    .bind(offset)
    .fetch_all(&mut **tx)
    .await?;
    Ok(Json(json!({"organizations":directory(rows)?,"total":total,"page":filters.page,"page_size":filters.size})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn catalog_counts_literal_matches_outside_the_requested_page() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE organizations(id uuid DEFAULT gen_random_uuid(),name text,
            short_name text,domain_name text,github_login text,description text,is_active bool,
            extra_metadata jsonb DEFAULT '{}',created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now());
            INSERT INTO organizations(name,short_name,github_login,is_active) VALUES
                ('First','x_y','',true),('Second','xay','',true),
                ('Third','x_y',null,true),('Fourth','x_y','',false);")
            .execute(&mut *tx).await.unwrap();
        let filters =
            Filters::parse("search=X_Y&has_github_login=1&is_active=true&page=2&page_size=1")
                .unwrap();
        let response = collection(&mut tx, filters).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"organizations":[],"total":1,"page":2,"page_size":1})
        );
    }
}
