//! Read privileged operation history from the shared PostgreSQL audit table.
use super::*;
use axum::extract::RawQuery;
use serde::Serialize;
use serde_json::value::RawValue;
use sqlx::{QueryBuilder, Row, postgres::PgRow};

mod verify;

pub(super) fn routes() -> Router<Arc<Profile>> {
    Router::new()
        .route("/api/v1/admin/audit", any(list))
        .route("/api/v1/admin/audit/verify", any(verify::read))
}

async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(a) => a,
        Err(e) => return *e,
    };
    let query = match Filters::parse(raw.as_deref().unwrap_or_default()) {
        Ok(f) => f,
        Err(e) => return passkeys::validation(e),
    };
    query
        .read(&mut tx)
        .await
        .map(|page| Json(page).into_response())
        .unwrap_or_else(|_| internal())
}

struct Filters {
    page: i128,
    size: i64,
    actor: Option<Uuid>,
    action: Option<String>,
    client: Option<String>,
    target_type: Option<String>,
    target_id: Option<String>,
}

impl Filters {
    fn parse(raw: &str) -> Result<Self, Vec<Value>> {
        let params = url::form_urlencoded::parse(raw.as_bytes()).collect();
        let mut issues = Vec::new();
        let (page, size) = crate::query::pagination(&params, 20, 100, &mut issues);
        let actor = params.get("actor_user_id").and_then(|id| {
            crate::query::uuid_field(id, "query", "actor_user_id")
                .map_err(|e| issues.push(e))
                .ok()
        });
        let mut text = |name, limit| {
            let v = params.get(name).filter(|v| !v.is_empty())?;
            if v.chars().count() > limit {
                issues.push(json!({"type":"string_too_long","loc":["query",name],"msg":format!("String should have at most {limit} characters"),"input":v,"ctx":{"max_length":limit.to_string()}}));
            }
            Some(v.to_string())
        };
        let filters = Self {
            page,
            size,
            actor,
            action: params
                .get("action")
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
            client: text("actor_client_id", 64),
            target_type: text("target_type", 32),
            target_id: text("target_id", 64),
        };
        if issues.is_empty() {
            Ok(filters)
        } else {
            Err(issues)
        }
    }

    fn query(&self, select: &str) -> QueryBuilder<'_, Postgres> {
        let mut sql = QueryBuilder::new(select.to_owned());
        sql.push(" FROM admin_action_logs WHERE true");
        if let Some(id) = self.actor {
            sql.push(" AND actor_user_id=").push_bind(id);
        }
        for (name, value) in [
            ("action", &self.action),
            ("actor_client_id", &self.client),
            ("target_type", &self.target_type),
            ("target_id", &self.target_id),
        ] {
            if let Some(v) = value {
                sql.push(" AND ").push(name).push("=").push_bind(v);
            }
        }
        sql
    }

    async fn read(&self, tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<Page> {
        let total = self
            .query("SELECT count(*)")
            .build_query_scalar()
            .fetch_one(&mut **tx)
            .await?;
        let offset = (self.page - 1)
            .checked_mul(self.size.into())
            .and_then(|n| i64::try_from(n).ok())
            .ok_or_else(|| {
                sqlx::Error::Protocol("audit page offset exceeds database range".into())
            })?;
        let mut sql = self.query(
            "SELECT id,actor_user_id,actor_email,actor_type,actor_client_id,action,
            target_type,target_id,extra_metadata::text AS metadata,created_at,
            host(ip_address) AS ip,masklen(ip_address) AS prefix",
        );
        sql.push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(self.size)
            .push(" OFFSET ")
            .push_bind(offset);
        let rows = sql.build().fetch_all(&mut **tx).await?;
        let entries = rows.iter().map(entry).collect::<sqlx::Result<_>>()?;
        Ok(Page {
            entries,
            total,
            page: self.page,
            page_size: self.size,
        })
    }
}

#[derive(Serialize)]
struct Page {
    entries: Vec<Entry>,
    total: i64,
    page: i128,
    page_size: i64,
}

#[derive(Serialize)]
struct Entry {
    id: Uuid,
    actor_user_id: Option<Uuid>,
    actor_email: Option<String>,
    actor_type: String,
    actor_client_id: Option<String>,
    action: String,
    target_type: Option<String>,
    target_id: Option<String>,
    metadata: Box<RawValue>,
    ip_address: Option<String>,
    created_at: String,
}

fn entry(row: &PgRow) -> sqlx::Result<Entry> {
    let actor_type = row
        .try_get::<Option<String>, _>("actor_type")?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "user".into());
    Ok(Entry {
        id: row.try_get("id")?,
        actor_user_id: row.try_get("actor_user_id")?,
        actor_email: row.try_get("actor_email")?,
        actor_type,
        actor_client_id: row.try_get("actor_client_id")?,
        action: row.try_get("action")?,
        target_type: row.try_get("target_type")?,
        target_id: row.try_get("target_id")?,
        metadata: metadata(row.try_get("metadata")?)?,
        ip_address: address(row.try_get("ip")?, row.try_get("prefix")?)?,
        created_at: timestamp(row.try_get("created_at")?),
    })
}

fn address(host: Option<&str>, prefix: Option<i32>) -> sqlx::Result<Option<String>> {
    let (Some(host), Some(prefix)) = (host, prefix) else {
        return Ok(None);
    };
    let ip = host
        .parse::<std::net::IpAddr>()
        .map_err(|e| sqlx::Error::Decode(e.into()))?;
    let width = if ip.is_ipv4() { 32 } else { 128 };
    let text = ip.to_string();
    Ok(Some(if prefix == width {
        text
    } else {
        format!("{text}/{prefix}")
    }))
}

fn metadata(raw: String) -> sqlx::Result<Box<RawValue>> {
    crate::stored_json::check_integers(&raw)?;
    if raw.starts_with('[') {
        let entries: Vec<&RawValue> =
            serde_json::from_str(&raw).map_err(|e| sqlx::Error::Decode(e.into()))?;
        for entry in entries.into_iter().filter(|v| v.get().starts_with('[')) {
            let pair: [&RawValue; 2] =
                serde_json::from_str(entry.get()).map_err(|e| sqlx::Error::Decode(e.into()))?;
            if !pair[0].get().starts_with('"') {
                return Err(sqlx::Error::Decode(
                    "audit metadata keys must be strings".into(),
                ));
            }
        }
    }
    let object = normalized_storage(&raw)?.unwrap_or(raw);
    RawValue::from_string(crate::stored_json::project_fractions(object, false)?)
        .map_err(|e| sqlx::Error::Decode(e.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_hosts_keep_dotted_ipv4_and_networks_keep_the_mask() {
        assert_eq!(
            address(Some("::ffff:192.0.2.4"), Some(128))
                .unwrap()
                .as_deref(),
            Some("::ffff:192.0.2.4")
        );
        assert_eq!(
            address(Some("198.51.100.1"), Some(24)).unwrap().as_deref(),
            Some("198.51.100.1/24")
        );
    }

    #[test]
    fn historical_metadata_retains_large_numbers_and_rejects_non_string_keys() {
        let number = "184467440737095516161234567890";
        let raw = format!(r#"[["counter",0],["counter",{number}],["details",{{"active":true}}]]"#);
        let object = metadata(raw).unwrap();
        assert!(object.get().contains(number));
        assert!(object.get().contains(r#""active":true"#));
        assert!(metadata("[[1,true]]".into()).is_err());
        assert_eq!(metadata("null".into()).unwrap().get(), "{}");
    }
}
