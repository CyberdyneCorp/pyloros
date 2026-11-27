//! Administrative user directory and account details.
use super::*;
use crate::{login_http::problem, query};
use axum::extract::{Path, RawQuery};
use sqlx::{Row, postgres::PgRow};
use std::collections::HashMap;

struct Filters {
    page: i128,
    size: i64,
    search: Option<String>,
    active: Option<bool>,
    verified: Option<bool>,
    organization: Option<Uuid>,
}

impl Filters {
    fn parse(raw: &str) -> Result<Self, Vec<Value>> {
        let fields: HashMap<_, _> = url::form_urlencoded::parse(raw.as_bytes()).collect();
        let mut issues = Vec::new();
        let (page, size) = query::pagination(&fields, 20, 100, &mut issues);
        let mut flag = |name| {
            fields
                .get(name)
                .and_then(|v| query::boolean(name, v).map_err(|e| issues.push(e)).ok())
        };
        let active = flag("is_active");
        let verified = flag("is_verified");
        let organization = fields.get("organization_id").and_then(|v| {
            query::uuid_field(v, "query", "organization_id")
                .map_err(|e| issues.push(e))
                .ok()
        });
        let search = fields
            .get("search")
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase());
        if issues.is_empty() {
            Ok(Self {
                page,
                size,
                active,
                verified,
                organization,
                search,
            })
        } else {
            Err(issues)
        }
    }
}

pub(super) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    if method != Method::GET {
        let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(header::ALLOW, "POST".parse().unwrap());
        return r;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let filters = match Filters::parse(raw.as_deref().unwrap_or("")) {
        Ok(v) => v,
        Err(e) => return passkeys::validation(e),
    };
    collection(&mut tx, &state.admins, filters)
        .await
        .unwrap_or_else(|_| internal())
}

pub(super) async fn detail(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (mut tx, id) = match target(&state, &method, &headers, &id).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    account(&mut tx, &state.admins, id)
        .await
        .unwrap_or_else(|_| internal())
}

pub(super) async fn target(
    state: &Profile,
    method: &Method,
    headers: &HeaderMap,
    raw: &str,
) -> Result<(Transaction<'static, Postgres>, Uuid), Box<Response>> {
    if method != Method::GET {
        return Err(Box::new(crate::browser_http::method_not_allowed().await));
    }
    let (tx, _, _) = administrator::operator(state, headers).await?;
    let user = query::path_uuid(raw, "user_id")
        .map_err(|issue| Box::new(passkeys::validation(vec![issue])))?;
    Ok((tx, user))
}

const COLUMNS: &str = "u.id,u.primary_email,u.default_wallet_address,u.created_at,u.is_active,
    u.is_email_verified,u.is_admin,u.password_hash IS NOT NULL AS has_password,u.extra_metadata->'avatar_url' AS avatar";
const FILTER: &str = "($1::text IS NULL OR strpos(lower(u.primary_email),$1)>0 OR strpos(lower(u.default_wallet_address),$1)>0)
    AND ($2::boolean IS NULL OR u.is_active=$2) AND ($3::boolean IS NULL OR u.is_email_verified=$3)
    AND ($4::uuid IS NULL OR u.organization_id=$4)";

async fn collection(
    tx: &mut Transaction<'_, Postgres>,
    admins: &[String],
    filters: Filters,
) -> Result<Response, sqlx::Error> {
    let Some(offset) = (filters.page - 1)
        .checked_mul(filters.size.into())
        .and_then(|n| i64::try_from(n).ok())
    else {
        return Ok(internal());
    };
    let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM users u WHERE {FILTER}"))
        .bind(&filters.search)
        .bind(filters.active)
        .bind(filters.verified)
        .bind(filters.organization)
        .fetch_one(&mut **tx)
        .await?;
    let sql = format!(
        "SELECT {COLUMNS},(SELECT count(*) FROM user_identities i WHERE i.user_id=u.id) AS identity_count
        FROM users u WHERE {FILTER} ORDER BY u.created_at DESC LIMIT $5 OFFSET $6"
    );
    let users = sqlx::query(&sql)
        .bind(&filters.search)
        .bind(filters.active)
        .bind(filters.verified)
        .bind(filters.organization)
        .bind(filters.size)
        .bind(offset)
        .try_map(|row| {
            let (mut doc, _) = summary(&row, admins)?;
            doc["identity_count"] = json!(row.try_get::<i64, _>("identity_count")?);
            Ok(doc)
        })
        .fetch_all(&mut **tx)
        .await?;
    Ok(
        Json(json!({"users":users,"total":total,"page":filters.page,"page_size":filters.size}))
            .into_response(),
    )
}

fn summary(row: &PgRow, admins: &[String]) -> Result<(Value, bool), sqlx::Error> {
    let email = row.try_get::<Option<&str>, _>("primary_email")?;
    let managed = config::bootstrap_admin(email, admins);
    let avatar = row
        .try_get::<Option<sqlx::types::Json<Option<String>>>, _>("avatar")?
        .and_then(|v| v.0);
    Ok((
        json!({
            "id":row.try_get::<Uuid,_>("id")?, "email":email, "wallet_address":row.try_get::<Option<&str>,_>("default_wallet_address")?,
            "created_at":timestamp(row.try_get("created_at")?), "is_active":row.try_get::<bool,_>("is_active")?,
            "is_email_verified":row.try_get::<bool,_>("is_email_verified")?, "is_admin":managed || row.try_get::<bool,_>("is_admin")?,
            "has_password":row.try_get::<bool,_>("has_password")?, "avatar_url":avatar
        }),
        managed,
    ))
}

async fn account(
    tx: &mut Transaction<'_, Postgres>,
    admins: &[String],
    id: Uuid,
) -> Result<Response, sqlx::Error> {
    let sql = format!(
        "SELECT {COLUMNS},u.primary_phone,u.public_key,u.organization_id,u.is_phone_verified,u.totp_enabled,u.updated_at,
        (SELECT max(s.last_used_at) FROM sessions s WHERE s.user_id=u.id) AS last_seen_at
        FROM users u WHERE u.id=$1"
    );
    let Some(row) = sqlx::query(&sql).bind(id).fetch_optional(&mut **tx).await? else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    let (mut doc, managed) = summary(&row, admins)?;
    let identities = sqlx::query_scalar::<_, Value>(
        "SELECT jsonb_build_object('id',id,'type',type,'provider',provider,'identifier',identifier)
         FROM user_identities WHERE user_id=$1",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    doc["phone"] = json!(row.try_get::<Option<&str>, _>("primary_phone")?);
    doc["public_key"] = json!(row.try_get::<Option<&str>, _>("public_key")?);
    doc["organization_id"] = json!(row.try_get::<Option<Uuid>, _>("organization_id")?);
    doc["is_phone_verified"] = json!(row.try_get::<bool, _>("is_phone_verified")?);
    doc["mfa_enabled"] = json!(row.try_get::<bool, _>("totp_enabled")?);
    doc["last_seen_at"] = json!(
        row.try_get::<Option<DateTime<Utc>>, _>("last_seen_at")?
            .map(timestamp)
    );
    doc["updated_at"] = json!(timestamp(row.try_get("updated_at")?));
    doc["is_admin_managed"] = json!(managed);
    doc["identities"] = json!(identities);
    doc["sessions"] = json!([]);
    Ok(Json(doc).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn directory_search_treats_wildcards_literally_and_counts_linked_identities() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid PRIMARY KEY, primary_email text,
            default_wallet_address text, created_at timestamptz DEFAULT now(),is_active boolean DEFAULT true,
            is_email_verified boolean DEFAULT false,is_admin boolean DEFAULT false,password_hash text,
            extra_metadata jsonb,organization_id uuid);
            CREATE TEMP TABLE user_identities(user_id uuid);
            INSERT INTO users(id,primary_email) VALUES (gen_random_uuid(),'a%_b@example.test'),(gen_random_uuid(),'axyb@example.test');
            INSERT INTO user_identities SELECT id FROM users WHERE primary_email='a%_b@example.test';")
            .execute(&mut *tx).await.unwrap();
        let filters = Filters::parse("search=%25_b&is_active=true&is_verified=no").unwrap();
        let response = collection(&mut tx, &["A%_B@example.test".into()], filters)
            .await
            .unwrap();
        let raw = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let page: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(page["total"], 1);
        let item = &page["users"][0];
        assert_eq!(item["identity_count"], 1);
        assert_eq!(item["is_admin"], true);
        assert_eq!(item["has_password"], false);
    }
}
