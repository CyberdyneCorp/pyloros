//! Paginated membership lookup for applications and administrators.
use super::*;
use crate::{login_http::problem, query};
use axum::extract::{Path, RawQuery};

async fn authorize(
    state: &Profile,
    headers: &HeaderMap,
) -> Result<Transaction<'static, Postgres>, Box<Response>> {
    if let Some(claims) = crate::csrf::bearer(headers)
        .and_then(|token| state.verify.as_ref()?.service_claims(token))
        .filter(|claims| claims["type"] == "service")
    {
        delegated::scoped_client(state, &claims, "directory:read").await?;
        return state.pool.begin().await.map_err(|_| Box::new(internal()));
    }
    administrator::operator(state, headers)
        .await
        .map(|(tx, _, _)| tx)
}

#[derive(serde::Serialize)]
struct Member {
    id: Uuid,
    email: Option<String>,
    avatar_url: Option<String>,
    is_active: bool,
}

fn avatar_url(stored: &str) -> Result<Option<String>, sqlx::Error> {
    #[derive(serde::Deserialize)]
    struct Metadata {
        avatar_url: Option<String>,
    }
    let normalized = admin_organizations::normalized_storage(stored)?;
    let metadata: Metadata = serde_json::from_str(normalized.as_deref().unwrap_or(stored))
        .map_err(|e| sqlx::Error::Decode(e.into()))?;
    Ok(metadata.avatar_url)
}

struct Directory {
    org: Uuid,
    page: i128,
    size: i64,
    search: Option<String>,
    active: Option<bool>,
}

impl Directory {
    fn parse(id: &str, raw: &str) -> Result<Self, Vec<Value>> {
        let fields = url::form_urlencoded::parse(raw.as_bytes()).collect();
        let mut errors = Vec::new();
        let org = query::path_uuid(id, "org_id")
            .map_err(|e| errors.push(e))
            .ok();
        let (page, size) = query::pagination(&fields, 50, 200, &mut errors);
        let active = fields.get("is_active").and_then(|s| {
            query::boolean("is_active", s)
                .map_err(|e| errors.push(e))
                .ok()
        });
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(Self {
            org: org.expect("validated organization ID"),
            page,
            size,
            active,
            search: fields
                .get("search")
                .filter(|s| !s.is_empty())
                .map(|s| s.to_lowercase()),
        })
    }

    async fn fetch(&self, tx: &mut Transaction<'_, Postgres>) -> Result<Response, sqlx::Error> {
        if !admin_organizations::active_organization(tx, self.org).await? {
            return Ok(problem(StatusCode::NOT_FOUND, "Organization not found"));
        }
        let Some(offset) = (self.page - 1)
            .checked_mul(self.size.into())
            .and_then(|n| i64::try_from(n).ok())
        else {
            return Ok(internal());
        };
        const FILTER: &str = "FROM users u WHERE (u.organization_id=$1 OR EXISTS
            (SELECT FROM user_organizations m WHERE m.organization_id=$1 AND m.user_id=u.id))
            AND ($2::text IS NULL OR strpos(lower(u.primary_email),$2)>0)
            AND ($3::boolean IS NULL OR u.is_active=$3)";
        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) {FILTER}"))
            .bind(self.org)
            .bind(&self.search)
            .bind(self.active)
            .fetch_one(&mut **tx)
            .await?;
        let sql = format!(
            "SELECT id,primary_email AS email,extra_metadata::text AS metadata,is_active
            {FILTER} ORDER BY created_at DESC,id LIMIT $4 OFFSET $5"
        );
        use sqlx::Row;
        let members = sqlx::query(&sql)
            .bind(self.org)
            .bind(&self.search)
            .bind(self.active)
            .bind(self.size)
            .bind(offset)
            .try_map(|row| {
                Ok(Member {
                    id: row.try_get("id")?,
                    email: row.try_get("email")?,
                    avatar_url: avatar_url(row.try_get("metadata")?)?,
                    is_active: row.try_get("is_active")?,
                })
            })
            .fetch_all(&mut **tx)
            .await?;
        Ok(
            Json(json!({"members":members,"total":total,"page":self.page,"page_size":self.size}))
                .into_response(),
        )
    }
}

pub(super) async fn read(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let mut tx = match authorize(&state, &headers).await {
        Ok(tx) => tx,
        Err(e) => return *e,
    };
    match Directory::parse(&id, raw.as_deref().unwrap_or_default()) {
        Ok(request) => request.fetch(&mut tx).await.unwrap_or_else(|_| internal()),
        Err(errors) => passkeys::validation(errors),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn scoped_search_counts_each_matching_member_once() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let org = Uuid::new_v4();
        sqlx::raw_sql(
            "CREATE TEMP TABLE organizations(id uuid, is_active boolean,extra_metadata jsonb DEFAULT '{}');
            CREATE TEMP TABLE user_organizations(user_id uuid, organization_id uuid);
            CREATE TEMP TABLE users(id uuid, organization_id uuid, primary_email text,
                extra_metadata jsonb DEFAULT '{}', is_active boolean, created_at timestamptz DEFAULT now());",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("INSERT INTO organizations(id,is_active) VALUES ($1,true)")
            .bind(org)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO users(id,organization_id,primary_email,is_active) VALUES
            (gen_random_uuid(),$1,'a%_b@example.test',true),
            (gen_random_uuid(),NULL,'linked%_b@example.test',true),
            (gen_random_uuid(),NULL,'outside%_b@example.test',true),
            (gen_random_uuid(),$1,'axxb@example.test',true)",
        )
        .bind(org)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_organizations SELECT id,$1 FROM users
            WHERE primary_email IN ('a%_b@example.test','linked%_b@example.test')",
        )
        .bind(org)
        .execute(&mut *tx)
        .await
        .unwrap();
        let request =
            Directory::parse(&org.to_string(), "search=%25_B&page_size=1&page=2").unwrap();
        let response = request.fetch(&mut tx).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["total"], 2);
        assert_eq!(doc["members"].as_array().unwrap().len(), 1);
        assert_eq!(doc["members"][0].as_object().unwrap().len(), 4);
    }

    #[test]
    fn legacy_pair_metadata_uses_the_last_avatar_value() {
        assert_eq!(
            avatar_url(r#"[["avatar_url","first"],["avatar_url","last"]]"#)
                .unwrap()
                .as_deref(),
            Some("last")
        );
        assert!(avatar_url("true").is_err());
    }

    #[test]
    fn directory_accumulates_path_and_query_errors_in_wire_order() {
        let errors = Directory::parse("bad", "page=0&page_size=201&is_active=wrong")
            .err()
            .unwrap();
        let locations: Vec<_> = errors.iter().map(|e| &e["loc"]).collect();
        assert_eq!(
            json!(locations),
            json!([
                ["path", "org_id"],
                ["query", "page"],
                ["query", "page_size"],
                ["query", "is_active"]
            ])
        );
    }
}
