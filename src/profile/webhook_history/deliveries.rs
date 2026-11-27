use super::*;
use std::collections::HashMap;

struct Page {
    id: Uuid,
    status: Option<String>,
    number: i128,
    size: i64,
}

impl Page {
    fn parse(raw: &str, query: &str) -> Result<Self, Vec<Value>> {
        let mut issues = Vec::new();
        let id = crate::query::path_uuid(raw, "subscription_id").unwrap_or_else(|e| {
            issues.push(e);
            Uuid::nil()
        });
        let params: HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes()).collect();
        let status = params.get("status").map(|v| v.to_string());
        if let Some(s) = &status
            && !valid_status(s)
        {
            let expected = "'pending', 'succeeded' or 'failed'";
            issues.push(json!({"type":"enum","loc":["query","status"],"input":s,"msg":format!("Input should be {expected}"),"ctx":{"expected":expected}}));
        }
        let (number, size) = crate::query::pagination(&params, 20, 100, &mut issues);
        if issues.is_empty() {
            Ok(Self {
                id,
                status,
                number,
                size,
            })
        } else {
            Err(issues)
        }
    }
}

fn valid_status(s: &str) -> bool {
    matches!(s, "pending" | "succeeded" | "failed")
}

pub(super) async fn read(
    State(state): State<Arc<Profile>>,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let mut tx = match operator(&state, method, &headers).await {
        Ok(tx) => tx,
        Err(e) => return *e,
    };
    let page = match Page::parse(&raw, query.as_deref().unwrap_or_default()) {
        Ok(p) => p,
        Err(issues) => return passkeys::validation(issues),
    };
    history(&mut tx, page).await.unwrap_or_else(|_| internal())
}

async fn history(tx: &mut Tx<'_>, page: Page) -> sqlx::Result<Response> {
    let Some(sub) = load(tx, page.id).await? else {
        return Ok(missing());
    };
    event_types(sub.try_get("events")?, false)?;
    for col in ["expires", "created", "updated"] {
        sub.try_get::<Option<&[u8]>, _>(col)?
            .map(event_time::EventTime::decode)
            .transpose()?;
    }
    let total:i64=sqlx::query_scalar("SELECT count(*) FROM webhook_deliveries WHERE subscription_id=$1 AND ($2::text IS NULL OR status=$2)")
        .bind(page.id).bind(&page.status).fetch_one(&mut **tx).await?;
    let offset = (page.number - 1)
        .checked_mul(page.size.into())
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| sqlx::Error::Protocol("page offset exceeds database range".into()))?;
    let rows=sqlx::query("SELECT d.id,d.subscription_id,d.event_id,e.type,d.status,d.attempt_count,d.last_status_code,d.last_error,
        timestamptz_send(d.next_attempt_at) AS due,timestamptz_send(d.created_at) AS created,timestamptz_send(d.updated_at) AS updated
        FROM webhook_deliveries d JOIN webhook_events e ON d.event_id=e.id
        WHERE d.subscription_id=$1 AND ($2::text IS NULL OR d.status=$2) ORDER BY d.created_at DESC,d.id LIMIT $3 OFFSET $4")
        .bind(page.id).bind(&page.status).bind(page.size).bind(offset).fetch_all(&mut **tx).await?;
    let ids = rows
        .iter()
        .map(|row| row.try_get("id"))
        .collect::<sqlx::Result<Vec<Uuid>>>()?;
    let mut attempts = attempts(tx, &ids).await?;
    let items = rows
        .iter()
        .zip(ids)
        .map(|(row, id)| delivery(row, id, attempts.remove(&id).unwrap_or_default()))
        .collect::<sqlx::Result<Vec<_>>>()?;
    Ok(
        Json(json!({"deliveries":items,"total":total,"page":page.number,"page_size":page.size}))
            .into_response(),
    )
}

fn delivery(row: &PgRow, id: Uuid, attempts: Vec<Value>) -> sqlx::Result<Value> {
    let status: &str = row.try_get("status")?;
    if !valid_status(status) {
        return Err(sqlx::Error::Decode("invalid stored delivery status".into()));
    }
    let next = time(row, "due")?;
    let event: Uuid = row.try_get("event_id")?;
    Ok(
        json!({"id":id,"subscription_id":row.try_get::<Uuid,_>("subscription_id")?,
        "event_type":row.try_get::<String,_>("type")?,"webhook_id":format!("msg_{}",event.simple()),
        "status":status,"attempt_count":row.try_get::<i32,_>("attempt_count")?,
        "next_attempt_at":(status=="pending").then_some(next),"last_status_code":row.try_get::<Option<i32>,_>("last_status_code")?,
        "last_error":row.try_get::<Option<String>,_>("last_error")?,"created_at":time(row,"created")?,
        "updated_at":time(row,"updated")?,"attempts":attempts}),
    )
}

async fn attempts(tx: &mut Tx<'_>, ids: &[Uuid]) -> sqlx::Result<HashMap<Uuid, Vec<Value>>> {
    let mut grouped = HashMap::<Uuid, Vec<Value>>::new();
    if ids.is_empty() {
        return Ok(grouped);
    }
    let rows=sqlx::query("SELECT delivery_id,timestamptz_send(attempted_at) AS attempted,status_code,error,duration_ms,response_excerpt
        FROM webhook_delivery_attempts WHERE delivery_id=ANY($1) ORDER BY attempted_at")
        .bind(ids).fetch_all(&mut **tx).await?;
    for row in rows {
        grouped.entry(row.try_get("delivery_id")?).or_default().push(json!({
            "attempted_at":time(&row,"attempted")?,"status_code":row.try_get::<Option<i32>,_>("status_code")?,
            "error":row.try_get::<Option<String>,_>("error")?,"duration_ms":row.try_get::<i32,_>("duration_ms")?,
            "response_excerpt":row.try_get::<Option<String>,_>("response_excerpt")?}));
    }
    Ok(grouped)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn combines_invalid_path_filter_and_page_fields() {
        let errors = Page::parse("bad", "status=done&page=0&page_size=101")
            .err()
            .unwrap();
        let keys: Vec<_> = errors
            .iter()
            .map(|e| e["loc"][1].as_str().unwrap())
            .collect();
        assert_eq!(keys, ["subscription_id", "status", "page", "page_size"]);
    }
}
