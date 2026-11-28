//! Read stored hook definitions and execution history for the administrator console.
use super::*;
mod author;
mod input;
mod removal;
use axum::extract::{DefaultBodyLimit, Path, RawQuery};
use sqlx::{Row, postgres::PgRow};
use std::collections::HashMap;

/// Supported hook event names in authoring validation order.
pub const HOOK_EVENTS: &[&str] = &[
    "entitlement_granted",
    "entitlement_revoked",
    "role_granted",
    "role_revoked",
    "user_deleted",
    "user_logged_in",
    "user_registered",
];

pub(super) fn routes() -> Router<Arc<Profile>> {
    Router::new()
        .route("/api/v1/admin/hooks", any(list).post(author::create))
        .route(
            "/api/v1/admin/hooks/validate",
            any(wasm_hooks::validate_source).put(author::update_reserved),
        )
        .route(
            "/api/v1/admin/hooks/{hook_id}",
            any(detail).put(author::update).delete(removal::remove),
        )
        .route(
            "/api/v1/admin/hooks/{hook_id}/test",
            any(|| async { passkeys::post_required() }).post(wasm_hooks::manual::test),
        )
        .layer(DefaultBodyLimit::disable())
        .route("/api/v1/admin/hooks/{hook_id}/executions", any(history))
}

const FIELDS: &str = "id,name,event_type,code,is_active,timeout_seconds,allow_network,receive_pii,
    timestamptz_send(created_at) AS created,timestamptz_send(updated_at) AS updated";

fn time(row: &PgRow, key: &str) -> sqlx::Result<String> {
    Ok(event_time::EventTime::decode(row.try_get(key)?)?.display("Z"))
}
fn event(row: &PgRow) -> sqlx::Result<&str> {
    let kind: &str = row.try_get("event_type")?;
    if HOOK_EVENTS.contains(&kind) {
        Ok(kind)
    } else {
        Err(sqlx::Error::Decode("unknown stored hook event".into()))
    }
}
fn hook(row: &PgRow) -> sqlx::Result<Value> {
    Ok(json!({
        "id":row.try_get::<Uuid,_>("id")?,"name":row.try_get::<&str,_>("name")?,
        "event_type":event(row)?,"code":row.try_get::<&str,_>("code")?,
        "is_active":row.try_get::<bool,_>("is_active")?,"timeout_seconds":row.try_get::<i32,_>("timeout_seconds")?,
        "allow_network":row.try_get::<bool,_>("allow_network")?,"receive_pii":row.try_get::<bool,_>("receive_pii")?,
        "created_at":time(row,"created")?,"updated_at":time(row,"updated")?
    }))
}
async fn list(State(state): State<Arc<Profile>>, method: Method, headers: HeaderMap) -> Response {
    let mut tx = match administrator::read(&state, method, &headers).await {
        Ok(tx) => tx,
        Err(e) => return *e,
    };
    let sql = format!("SELECT {FIELDS} FROM hooks ORDER BY created_at DESC");
    let hooks = sqlx::query(&sql)
        .fetch_all(&mut *tx)
        .await
        .and_then(|rows| rows.iter().map(hook).collect::<sqlx::Result<Vec<_>>>());
    match hooks {
        Ok(hooks) => Json(json!({"total":hooks.len(),"hooks":hooks})).into_response(),
        Err(_) => internal(),
    }
}
async fn detail(
    State(state): State<Arc<Profile>>,
    Path(raw): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let mut tx = match administrator::read(&state, method, &headers).await {
        Ok(tx) => tx,
        Err(e) => return *e,
    };
    let id = match crate::query::path_uuid(&raw, "hook_id") {
        Ok(id) => id,
        Err(e) => return passkeys::validation(vec![e]),
    };
    let sql = format!("SELECT {FIELDS} FROM hooks WHERE id=$1");
    match sqlx::query(&sql)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .and_then(|row| row.as_ref().map(hook).transpose())
    {
        Ok(Some(h)) => Json(h).into_response(),
        Ok(None) => missing(),
        Err(_) => internal(),
    }
}
fn missing() -> Response {
    crate::login_http::problem(StatusCode::NOT_FOUND, "Hook not found")
}

struct Page {
    id: Uuid,
    limit: i64,
    offset: i128,
}
impl Page {
    fn parse(raw: &str, query: &str) -> Result<Self, Vec<Value>> {
        let params: HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes()).collect();
        let mut issues = Vec::new();
        let id = crate::query::path_uuid(raw, "hook_id").unwrap_or_else(|e| {
            issues.push(e);
            Uuid::nil()
        });
        let mut number = |name, default, min, max| {
            params.get(name).map_or(default, |raw| {
                crate::query::range(name, raw, min, max).unwrap_or_else(|e| {
                    issues.push(e);
                    default
                })
            })
        };
        let limit = number("limit", 50, 1, Some(100)) as i64;
        let offset = number("offset", 0, 0, None);
        if issues.is_empty() {
            Ok(Self { id, limit, offset })
        } else {
            Err(issues)
        }
    }
}
async fn history(
    State(state): State<Arc<Profile>>,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let mut tx = match administrator::read(&state, method, &headers).await {
        Ok(tx) => tx,
        Err(e) => return *e,
    };
    let p = match Page::parse(&raw, query.as_deref().unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return passkeys::validation(e),
    };
    read_history(&mut tx, p)
        .await
        .unwrap_or_else(|_| internal())
}
async fn read_history(tx: &mut Transaction<'_, Postgres>, p: Page) -> sqlx::Result<Response> {
    let offset = i64::try_from(p.offset)
        .map_err(|_| sqlx::Error::Protocol("offset exceeds database range".into()))?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM hook_executions WHERE hook_id=$1")
        .bind(p.id)
        .fetch_one(&mut **tx)
        .await?;
    let rows=sqlx::query("SELECT id,hook_id,hook_name,event_type,user_id,status,error_message,output,execution_time_ms,
        context_snapshot::text AS context,timestamptz_send(created_at) AS created FROM hook_executions WHERE hook_id=$1
        ORDER BY created_at DESC LIMIT $2 OFFSET $3").bind(p.id).bind(p.limit).bind(offset).fetch_all(&mut **tx).await?;
    let executions = rows
        .iter()
        .map(execution)
        .collect::<sqlx::Result<Vec<_>>>()?;
    Ok(Json(json!({"total":total,"executions":executions})).into_response())
}
fn execution(row: &PgRow) -> sqlx::Result<Value> {
    let status: &str = row.try_get("status")?;
    if !matches!(status, "success" | "failed" | "timeout") {
        return Err(sqlx::Error::Decode(
            "unknown stored execution status".into(),
        ));
    }
    let context: &str = row.try_get("context")?;
    crate::stored_json::check_integers(context)?;
    normalized_storage(context)?;
    Ok(json!({
        "id":row.try_get::<Uuid,_>("id")?,"hook_id":row.try_get::<Uuid,_>("hook_id")?,
        "hook_name":row.try_get::<&str,_>("hook_name")?,"event_type":event(row)?,"user_id":row.try_get::<Option<Uuid>,_>("user_id")?,
        "status":status,"error_message":row.try_get::<Option<&str>,_>("error_message")?,
        "output":row.try_get::<Option<&str>,_>("output")?,"execution_time_ms":row.try_get::<Option<i32>,_>("execution_time_ms")?,
        "created_at":time(row,"created")?
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_validation_reports_path_and_both_bounds_in_order() {
        let errs = Page::parse("bad", "limit=0&offset=-1").err().unwrap();
        assert_eq!(errs.len(), 3);
        assert_eq!(errs[0]["loc"], json!(["path", "hook_id"]));
        assert_eq!(errs[1]["ctx"], json!({"ge":"1"}));
        assert_eq!(errs[2]["ctx"], json!({"ge":"0"}));
        let p = Page::parse(&Uuid::nil().to_string(), "offset=7&offset=0&limit=1.0").unwrap();
        assert_eq!((p.limit, p.offset), (1, 0));
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn history_projects_only_the_requested_records_and_excludes_private_context() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE hook_executions(id uuid,hook_id uuid,hook_name text,event_type text,user_id uuid,status text,error_message text,output text,execution_time_ms integer,context_snapshot jsonb,created_at timestamptz)")
            .execute(&mut *tx).await.unwrap();
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO hook_executions VALUES
            (gen_random_uuid(),$1,'prior name','user_registered',NULL,'success',NULL,'first',3,'{}',now()-interval '1 day'),
            (gen_random_uuid(),$1,'current name','role_granted',NULL,'timeout','deadline',NULL,5000,'{\"internal\":true}',now())")
            .bind(id).execute(&mut *tx).await.unwrap();
        let response = read_history(
            &mut tx,
            Page {
                id,
                limit: 1,
                offset: 0,
            },
        )
        .await
        .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["total"], 2);
        assert_eq!(doc["executions"].as_array().unwrap().len(), 1);
        let item = &doc["executions"][0];
        assert_eq!(item["status"], "timeout");
        assert_eq!(item["hook_name"], "current name");
        assert!(item.get("context_snapshot").is_none());
        assert!(item["output"].is_null());
    }
}
