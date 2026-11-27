//! Administrative entitlement directory and subscriber counts.
use super::*;
use axum::extract::RawQuery;
use sqlx::{Row, postgres::PgRow};
use std::collections::HashMap;
mod stats;

pub(super) fn routes() -> Router<Arc<Profile>> {
    Router::new()
        .route("/api/v1/admin/entitlements", any(list))
        .route("/api/v1/admin/entitlements/stats", any(stats::read))
}

struct Filters {
    user: Option<Uuid>,
    org: Option<Uuid>,
    product: Option<String>,
    page: i128,
    size: i64,
}

impl Filters {
    fn parse(raw: &str) -> Result<Self, Vec<Value>> {
        let params = url::form_urlencoded::parse(raw.as_bytes()).collect();
        let mut issues = Vec::new();
        let (page, size) = crate::query::pagination(&params, 50, 200, &mut issues);
        let mut id = |name| {
            params.get(name).and_then(|value| {
                crate::query::uuid_field(value, "query", name)
                    .map_err(|issue| issues.push(issue))
                    .ok()
            })
        };
        let user = id("user_id");
        let org = id("organization_id");
        if !issues.is_empty() {
            return Err(issues);
        }
        Ok(Self {
            user,
            org,
            product: params.get("product_key").map(|v| v.to_string()),
            page,
            size,
        })
    }
}

async fn list(
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
        Err(e) => return *e,
    };
    let filters = match Filters::parse(query.as_deref().unwrap_or_default()) {
        Ok(filters) => filters,
        Err(errors) => return passkeys::validation(errors),
    };
    inventory(&mut tx, &filters)
        .await
        .map(|doc| Json(doc).into_response())
        .unwrap_or_else(|_| internal())
}

async fn inventory(tx: &mut Transaction<'_, Postgres>, f: &Filters) -> sqlx::Result<Value> {
    let offset = (f.page - 1)
        .checked_mul(f.size.into())
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| sqlx::Error::Protocol("page offset exceeds database range".into()))?;
    const FILTER: &str = "FROM entitlements WHERE ($1::uuid IS NULL OR user_id=$1)
        AND ($2::uuid IS NULL OR organization_id=$2) AND ($3::text IS NULL OR product_key=$3)";
    let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) {FILTER}"))
        .bind(f.user)
        .bind(f.org)
        .bind(&f.product)
        .fetch_one(&mut **tx)
        .await?;
    let rows=sqlx::query(&format!("SELECT *,extra_metadata::text AS metadata {FILTER} ORDER BY created_at DESC LIMIT $4 OFFSET $5"))
        .bind(f.user).bind(f.org).bind(&f.product).bind(f.size).bind(offset).fetch_all(&mut **tx).await?;
    let mut users = Vec::new();
    let mut orgs = Vec::new();
    for row in &rows {
        users.extend(row.try_get::<Option<Uuid>, _>("user_id")?);
        users.extend(row.try_get::<Option<Uuid>, _>("granted_by_user_id")?);
        orgs.extend(row.try_get::<Option<Uuid>, _>("organization_id")?);
    }
    let emails = labels(
        tx,
        &users,
        "SELECT id,primary_email,extra_metadata::text FROM users WHERE id=ANY($1)",
    )
    .await?;
    let names = labels(
        tx,
        &orgs,
        "SELECT id,name,extra_metadata::text FROM organizations WHERE id=ANY($1)",
    )
    .await?;
    let grants = rows
        .iter()
        .map(|row| item(row, &emails, &names))
        .collect::<sqlx::Result<Vec<_>>>()?;
    Ok(json!({"entitlements":grants,"page":f.page,"page_size":f.size,"total":total}))
}

type Labels = HashMap<Uuid, Option<String>>;

async fn labels(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[Uuid],
    sql: &str,
) -> sqlx::Result<Labels> {
    let mut labels = HashMap::new();
    if !ids.is_empty() {
        for (id, label, metadata) in sqlx::query_as::<_, (Uuid, Option<String>, String)>(sql)
            .bind(ids)
            .fetch_all(&mut **tx)
            .await?
        {
            administrator::validate_metadata(&metadata)?;
            labels.insert(id, label);
        }
    }
    Ok(labels)
}

fn item(row: &PgRow, emails: &Labels, names: &Labels) -> sqlx::Result<Value> {
    administrator::validate_metadata(row.try_get("metadata")?)?;
    let status: &str = row.try_get("status")?;
    let source: &str = row.try_get("source")?;
    if !matches!(status, "active" | "revoked" | "expired")
        || !matches!(source, "admin" | "stripe" | "nft" | "apple" | "google")
    {
        return Err(sqlx::Error::Decode(
            "unknown entitlement status or source".into(),
        ));
    }
    let product: &str = row.try_get("product_key")?;
    let plan: Option<&str> = row.try_get("plan")?;
    let token = plan
        .filter(|p| !p.is_empty())
        .map_or_else(|| product.to_string(), |plan| format!("{product}:{plan}"));
    let mut item = json!({"id":row.try_get::<Uuid,_>("id")?, "product_key":product,"plan":plan,"token":token,
        "source":source,"status":status,"external_ref":row.try_get::<Option<String>,_>("external_ref")?});
    for (field, label, lookup) in [
        ("user_id", "user_email", emails),
        ("granted_by_user_id", "granted_by_email", emails),
        ("organization_id", "organization_name", names),
    ] {
        let id = row.try_get::<Option<Uuid>, _>(field)?;
        item[field] = json!(id);
        item[label] = json!(id.and_then(|i| lookup.get(&i)));
    }
    for date in ["created_at", "updated_at", "expires_at", "revoked_at"] {
        item[date] = json!(
            row.try_get::<Option<DateTime<Utc>>, _>(date)?
                .map(timestamp)
        );
    }
    Ok(item)
}
