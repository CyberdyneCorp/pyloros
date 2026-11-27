//! Administrative inventory and revocation of account sessions.
use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
};
use axum::extract::{Path, RawQuery};
use sqlx::{Row, postgres::PgRow};
use std::collections::HashMap;

struct Filters {
    page: i128,
    size: i64,
    owner: Option<Uuid>,
    active: bool,
}
impl Filters {
    fn parse(query: &str) -> Result<Self, Vec<Value>> {
        let fields: HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes()).collect();
        let mut issues = Vec::new();
        let (page, size) = crate::query::pagination(&fields, 20, 100, &mut issues);
        let owner = fields.get("user_id").and_then(|value| {
            match crate::query::uuid_field(value, "query", "user_id") {
                Ok(owner) => Some(owner),
                Err(issue) => {
                    issues.push(issue);
                    None
                }
            }
        });
        let active = crate::query::active_only(Some(
            fields.get("active_only").map_or("true", |s| s.as_ref()),
        ))
        .unwrap_or_else(|e| {
            issues.push(e);
            true
        });
        if issues.is_empty() {
            Ok(Self {
                page,
                size,
                owner,
                active,
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
    RawQuery(query): RawQuery,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match operator(&state, &headers).await {
        Ok(context) => context,
        Err(r) => return *r,
    };
    let filters = match Filters::parse(query.as_deref().unwrap_or("")) {
        Ok(f) => f,
        Err(e) => return passkeys::validation(e),
    };
    inventory(&mut tx, filters)
        .await
        .unwrap_or_else(|_| internal())
}
const FILTER: &str =
    "($1::uuid IS NULL OR s.user_id=$1) AND (NOT $2 OR (s.revoked_at IS NULL AND s.expires_at>$3))";

async fn inventory(
    tx: &mut Transaction<'_, Postgres>,
    filters: Filters,
) -> Result<Response, sqlx::Error> {
    let Some(offset) = (filters.page - 1)
        .checked_mul(filters.size.into())
        .and_then(|n| i64::try_from(n).ok())
    else {
        return Ok(internal());
    };
    let now = Utc::now();
    let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM sessions s WHERE {FILTER}"))
        .bind(filters.owner)
        .bind(filters.active)
        .bind(now)
        .fetch_one(&mut **tx)
        .await?;
    let sql = format!(
        "SELECT s.id,s.user_id,u.primary_email,s.user_agent,abbrev(s.ip_address) AS ip,
        s.created_at,s.expires_at,s.last_used_at FROM sessions s LEFT JOIN users u ON u.id=s.user_id
        WHERE {FILTER} ORDER BY s.created_at DESC LIMIT $4 OFFSET $5"
    );
    let sessions = sqlx::query(&sql)
        .bind(filters.owner)
        .bind(filters.active)
        .bind(now)
        .bind(filters.size)
        .bind(offset)
        .try_map(document)
        .fetch_all(&mut **tx)
        .await?;
    Ok(Json(
        json!({"sessions":sessions,"page":filters.page,"page_size":filters.size,"total":total}),
    )
    .into_response())
}

fn document(row: PgRow) -> Result<Value, sqlx::Error> {
    Ok(json!({
        "id":row.try_get::<Uuid,_>("id")?,
        "user_id":row.try_get::<Uuid,_>("user_id")?,
        "user_email":row.try_get::<Option<String>,_>("primary_email")?,
        "user_agent":row.try_get::<Option<String>,_>("user_agent")?,
        "ip_address":row.try_get::<Option<String>,_>("ip")?,
        "last_used_at":timestamp(row.try_get("last_used_at")?),
        "created_at":timestamp(row.try_get("created_at")?),
        "expires_at":timestamp(row.try_get("expires_at")?)
    }))
}

async fn operator(
    state: &Profile,
    headers: &HeaderMap,
) -> Result<(Transaction<'static, Postgres>, Uuid, Option<String>), Box<Response>> {
    let identity =
        administrator::identity(state, headers).ok_or_else(|| Box::new(unauthorized()))?;
    let (tx, email) = administrator::session(state, &identity).await?;
    Ok((tx, identity.user, email))
}

pub(super) async fn revoke(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(target): Path<String>,
) -> Response {
    if method != Method::DELETE {
        let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, "DELETE".parse().unwrap());
        return response;
    }
    let (tx, admin, email) = match operator(&state, &headers).await {
        Ok(context) => context,
        Err(r) => return *r,
    };
    let session = match crate::query::path_uuid(&target, "session_id") {
        Ok(s) => s,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    end_session(
        tx,
        session,
        (admin, email.as_deref()),
        origin,
        crate::token_http::header(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn end_session(
    mut tx: Transaction<'_, Postgres>,
    session: Uuid,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let now = Utc::now();
    let user = sqlx::query_scalar::<_, Uuid>(
        "UPDATE sessions SET revoked_at=$2 WHERE id=$1 RETURNING user_id",
    )
    .bind(session)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(user) = user else {
        return Ok(problem(StatusCode::NOT_FOUND, "Session not found"));
    };
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at=$2 WHERE session_id=$1 AND revoked_at IS NULL",
    )
    .bind(session)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let (email, organization) = sqlx::query_as::<_, (Option<String>, Option<Uuid>)>(
        "SELECT primary_email,organization_id FROM users WHERE id=$1",
    )
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or_default();
    write_activity(
        &mut *tx,
        AuditActivity::SessionRevoked {
            operator: actor.0,
            session,
        },
        AuditSubject {
            user: Some(user),
            email,
            organization,
        },
        origin,
        request,
        now,
    )
    .await?;
    crate::admin_audit::append(
        &mut tx,
        "session.revoke",
        Some(actor),
        ("session", &session.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_invalid_session_filters_in_parameter_order() {
        let issues = Filters::parse("active_only=x&user_id=z&page_size=101&page=0")
            .err()
            .unwrap();
        let fields: Vec<_> = issues
            .iter()
            .map(|issue| issue["loc"][1].as_str().unwrap())
            .collect();
        assert_eq!(fields, ["page", "page_size", "user_id", "active_only"]);
        assert_eq!(issues[1]["ctx"], json!({"le":"100"}));
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn pages_and_totals_respect_owner_expiration_and_revocation() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid PRIMARY KEY,primary_email text);
            CREATE TEMP TABLE sessions(id uuid,user_id uuid,user_agent text,ip_address inet,
            created_at timestamptz,expires_at timestamptz,last_used_at timestamptz,revoked_at timestamptz);")
            .execute(&mut *tx).await.unwrap();
        let owner = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES ($1,'test@example.org')")
            .bind(owner)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions SELECT gen_random_uuid(),CASE WHEN n=4 THEN gen_random_uuid() ELSE $1 END,
            NULL,'2001:db8::1'::inet,now()-n*interval '1 hour',
            CASE WHEN n=2 THEN now()-interval '1 hour' ELSE now()+interval '1 day' END,
            now(),CASE WHEN n=3 THEN now() END FROM generate_series(1,4) n")
            .bind(owner).execute(&mut *tx).await.unwrap();
        let filters = Filters::parse(&format!("user_id={owner}")).unwrap();
        let response = inventory(&mut tx, filters).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["total"], 1);
        assert_eq!(doc["sessions"][0]["ip_address"], "2001:db8::1");
        assert_eq!(doc["sessions"][0]["user_email"], "test@example.org");
    }
}
