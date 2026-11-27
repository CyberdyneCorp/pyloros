//! Administrative subscription inventory and delivery history.
use super::*;
use crate::login_http::problem;
use axum::extract::{Path, RawQuery};
use sqlx::{Row, postgres::PgRow};
mod deliveries;
type Tx<'a> = Transaction<'a, Postgres>;

pub(super) fn routes() -> Router<Arc<Profile>> {
    Router::new()
        .route("/api/v1/admin/webhooks", any(list))
        .route("/api/v1/admin/webhooks/{subscription_id}", any(detail))
        .route(
            "/api/v1/admin/webhooks/{subscription_id}/deliveries",
            any(deliveries::read),
        )
}

async fn operator(
    state: &Profile,
    method: Method,
    headers: &HeaderMap,
) -> Result<Tx<'static>, Box<Response>> {
    if method != Method::GET {
        return Err(Box::new(crate::browser_http::method_not_allowed().await));
    }
    administrator::operator(state, headers)
        .await
        .map(|(tx, _, _)| tx)
}

const SUBSCRIPTION: &str = "SELECT id,name,url,description,is_active,event_types::text AS events,
    timestamptz_send(previous_secret_expires_at) AS expires,timestamptz_send(created_at) AS created,
    timestamptz_send(updated_at) AS updated FROM webhook_subscriptions";

async fn list(State(state): State<Arc<Profile>>, method: Method, headers: HeaderMap) -> Response {
    let mut tx = match operator(&state, method, &headers).await {
        Ok(tx) => tx,
        Err(e) => return *e,
    };
    inventory(&mut tx).await.unwrap_or_else(|_| internal())
}

async fn inventory(tx: &mut Tx<'_>) -> sqlx::Result<Response> {
    let rows = sqlx::query(&format!("{SUBSCRIPTION} ORDER BY created_at DESC"))
        .fetch_all(&mut **tx)
        .await?;
    let now = Utc::now();
    let items = rows
        .iter()
        .map(|r| subscription(r, now))
        .collect::<sqlx::Result<Vec<_>>>()?;
    Ok(Json(json!({"total":items.len(),"webhooks":items})).into_response())
}

async fn detail(
    State(state): State<Arc<Profile>>,
    Path(raw): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let mut tx = match operator(&state, method, &headers).await {
        Ok(tx) => tx,
        Err(e) => return *e,
    };
    let id = match crate::query::path_uuid(&raw, "subscription_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    match load(&mut tx, id).await {
        Ok(Some(row)) => subscription(&row, Utc::now())
            .map(|v| Json(v).into_response())
            .unwrap_or_else(|_| internal()),
        Ok(None) => missing(),
        Err(_) => internal(),
    }
}

async fn load(tx: &mut Tx<'_>, id: Uuid) -> sqlx::Result<Option<PgRow>> {
    sqlx::query(&format!("{SUBSCRIPTION} WHERE id=$1"))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
}
fn missing() -> Response {
    problem(StatusCode::NOT_FOUND, "Webhook subscription not found")
}
fn time(row: &PgRow, key: &str) -> sqlx::Result<String> {
    Ok(event_time::EventTime::decode(row.try_get(key)?)?.display("Z"))
}

fn subscription(row: &PgRow, now: DateTime<Utc>) -> sqlx::Result<Value> {
    let events = event_types(row.try_get("events")?, true)?;
    let expires: Option<&[u8]> = row.try_get("expires")?;
    let rotating = expires
        .map(event_time::EventTime::decode)
        .transpose()?
        .is_some_and(|t| t.utc > now);
    Ok(
        json!({"id":row.try_get::<Uuid,_>("id")?, "name":row.try_get::<String,_>("name")?,
        "url":row.try_get::<String,_>("url")?, "description":row.try_get::<Option<String>,_>("description")?,
        "is_active":row.try_get::<bool,_>("is_active")?, "event_types":events,"secret_rotation_in_progress":rotating,
        "created_at":time(row,"created")?, "updated_at":time(row,"updated")?}),
    )
}

fn event_types(raw: &str, validate_strings: bool) -> sqlx::Result<Vec<String>> {
    use serde_json::value::RawValue;
    crate::stored_json::check_integers(raw)?;
    let error = || sqlx::Error::Decode("invalid stored webhook event types".into());
    match raw.as_bytes().first() {
        Some(b'[') if !validate_strings => Ok(vec![]),
        Some(b'[') => serde_json::from_str(raw).map_err(|_| error()),
        Some(b'{') => {
            let fields: std::collections::HashMap<String, &RawValue> =
                serde_json::from_str(raw).map_err(|_| error())?;
            let mut keys: Vec<_> = fields.into_keys().collect();
            keys.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
            Ok(keys)
        }
        Some(b'"') => Ok(serde_json::from_str::<String>(raw)
            .map_err(|_| error())?
            .chars()
            .map(|c| c.to_string())
            .collect()),
        _ if matches!(raw, "null" | "false") || raw.parse::<f64>() == Ok(0.0) => Ok(vec![]),
        _ => Err(error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_event_types_preserve_order_and_validate_response_items() {
        assert_eq!(
            event_types(r#"["b","a","b"]"#, true).unwrap(),
            ["b", "a", "b"]
        );
        assert_eq!(
            event_types(r#"{"aaa":1,"z":2}"#, true).unwrap(),
            ["z", "aaa"]
        );
        assert!(event_types("[1]", true).is_err());
        assert!(event_types("[1]", false).is_ok());
        assert!(event_types("true", false).is_err());
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn inventory_reports_rotation_without_loading_signing_material() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE webhook_subscriptions(id uuid DEFAULT gen_random_uuid(),name text,url text,
            is_active bool,description text,event_types jsonb,created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now(),
            previous_secret_expires_at timestamptz);
            INSERT INTO webhook_subscriptions(name,url,is_active,event_types,previous_secret_expires_at)
            VALUES('Paused','https://example.test',false,'[\"user.created\"]',now()+interval '1 day');")
            .execute(&mut *tx).await.unwrap();
        let response = inventory(&mut tx).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let result: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["total"], 1);
        assert_eq!(result["webhooks"][0]["secret_rotation_in_progress"], true);
        assert_eq!(result["webhooks"][0]["is_active"], false);
        assert_eq!(
            result["webhooks"][0]["event_types"],
            json!(["user.created"])
        );
    }
}
