//! Global and subject-scoped authentication event history.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem};
use axum::extract::{ConnectInfo, Path};
use std::collections::HashMap;
mod catalog;
mod cursor;
mod query;
use cursor::Cursor;
use query::Filters;

pub(super) fn routes() -> Router<Arc<Profile>> {
    Router::new()
        .route("/api/v1/admin/auth-events", any(read))
        .route("/api/v1/admin/users/{user_id}/auth-events", any(read))
}

async fn read(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<HashMap<String, String>>,
    RawQuery(raw): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(a) => a,
        Err(e) => return *e,
    };
    let subject = path.get("user_id").map(String::as_str);
    let filters = match Filters::parse(subject, raw.as_deref().unwrap_or_default()) {
        Ok(f) => f,
        Err(e) => return passkeys::validation(e),
    };
    let cursor = match filters.cursor.as_deref().map(Cursor::decode) {
        Some(None) => return problem(StatusCode::BAD_REQUEST, "Invalid cursor"),
        Some(c) => c,
        None => None,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    let target = subject.and(filters.user);
    search(tx, filters, cursor, (actor, email), target, origin)
        .await
        .unwrap_or_else(|_| internal())
}

#[derive(Serialize)]
struct Event {
    #[serde(flatten)]
    fields: Value,
    details: Box<RawValue>,
}

#[derive(Serialize)]
struct Page {
    events: Vec<Event>,
    next_cursor: Option<String>,
}

async fn search(
    mut tx: Transaction<'_, Postgres>,
    mut filters: Filters,
    cursor: Option<Cursor>,
    (actor, email): (Uuid, Option<String>),
    target: Option<Uuid>,
    origin: SessionOrigin<'_>,
) -> sqlx::Result<Response> {
    let page = fetch_page(&mut tx, &filters, cursor).await?;
    filters
        .audit
        .insert("returned".into(), json!(page.events.len()));
    let id = target.map(|v| v.to_string());
    crate::admin_audit::append_record(
        &mut tx,
        "auth_events.read",
        Some((actor, email.as_deref())),
        id.as_deref().map(|v| ("user", Some(v))),
        Value::Object(filters.audit),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(page).into_response())
}

async fn fetch_page(
    tx: &mut Transaction<'_, Postgres>,
    f: &Filters,
    cursor: Option<Cursor>,
) -> sqlx::Result<Page> {
    let mut sql=QueryBuilder::new("SELECT id,timestamptz_send(occurred_at) AS event_time,
        host(ip_address) AS ip,masklen(ip_address) AS prefix,details::text AS metadata,
        jsonb_build_object('id',id,'activity',activity,'outcome',outcome,'reason_code',reason_code,
        'auth_protocol',auth_protocol,'is_mfa',is_mfa,'subject_format',subject_format,
        'subject_user_id',subject_user_id,'subject_email',subject_email,'subject_issuer',subject_issuer,
        'subject_identifier',subject_identifier,'actor_type',actor_type,'actor_user_id',actor_user_id,
        'actor_client_id',actor_client_id,'client_id',client_id,'organization_id',organization_id,
        'user_agent',user_agent,'request_id',request_id,'content_hash',content_hash,
        'schema_version',schema_version) AS fields FROM auth_events WHERE true");
    apply_filters(&mut sql, f)?;
    if let Some(c) = cursor {
        sql.push(" AND (occurred_at,id)<(")
            .push_bind(c.at)
            .push(",")
            .push_bind(c.id)
            .push(")");
    }
    sql.push(" ORDER BY occurred_at DESC,id DESC LIMIT ")
        .push_bind(f.limit + 1);
    let rows = sql.build().fetch_all(&mut **tx).await?;
    let mut events = Vec::with_capacity(rows.len().min(f.limit as usize));
    let mut next_cursor = None;
    for (i, row) in rows.iter().enumerate() {
        let at = EventTime::read(row)?.utc;
        crate::stored_json::check_integers(row.try_get("metadata")?)?;
        if i < f.limit as usize {
            events.push(event(row, at)?);
            if i + 1 == f.limit as usize && rows.len() > i + 1 {
                next_cursor = Some(
                    Cursor {
                        at,
                        id: row.try_get("id")?,
                    }
                    .encode(),
                );
            }
        }
    }
    Ok(Page {
        events,
        next_cursor,
    })
}

fn apply_filters(sql: &mut QueryBuilder<'_, Postgres>, f: &Filters) -> sqlx::Result<()> {
    for key in [
        "subject_email",
        "client_id",
        "activity",
        "outcome",
        "reason_code",
    ] {
        if let Some(value) = f.audit.get(key).and_then(Value::as_str) {
            let value = if key == "subject_email" {
                admin_fields::trimmed(value)
                    .to_lowercase()
                    .chars()
                    .take(320)
                    .collect()
            } else {
                value.to_string()
            };
            sql.push(" AND ").push(key).push("=").push_bind(value);
        }
    }
    for (key, id) in [("subject_user_id", f.user), ("actor_user_id", f.actor)] {
        if let Some(id) = id {
            sql.push(" AND ").push(key).push("=").push_bind(id);
        }
    }
    for (bound, clause) in [
        (&f.start, " AND occurred_at >= "),
        (&f.end, " AND occurred_at <= "),
    ] {
        if let Some(date) = bound {
            date.check_utc_year()?;
            sql.push(clause).push_bind(date.utc);
        }
    }
    Ok(())
}

fn event(row: &PgRow, at: DateTime<Utc>) -> sqlx::Result<Event> {
    let mut fields: Value = row.try_get("fields")?;
    let activity = fields["activity"].as_str().unwrap_or_default();
    let (class, _) = catalog::CLASSES
        .iter()
        .find(|(_, values)| values.contains(&activity))
        .ok_or_else(|| sqlx::Error::Decode("unknown authentication activity".into()))?;
    for (key, allowed, optional) in [
        ("outcome", catalog::OUTCOMES, false),
        ("actor_type", catalog::ACTORS, false),
        ("reason_code", catalog::REASONS, true),
        ("auth_protocol", catalog::PROTOCOLS, true),
        ("subject_format", catalog::FORMATS, true),
    ] {
        let value = fields[key].as_str().unwrap_or_default();
        if optional && value.is_empty() {
            fields[key] = Value::Null;
        } else if !allowed.contains(&value) {
            return Err(sqlx::Error::Decode(format!("unknown event {key}").into()));
        }
    }
    fields["event_class"] = json!(class);
    fields["occurred_at"] = json!(timestamp(at));
    fields["ip_address"] = json!(address(row.try_get("ip")?, row.try_get("prefix")?)?);
    Ok(Event {
        fields,
        details: metadata(row.try_get("metadata")?)?,
    })
}
