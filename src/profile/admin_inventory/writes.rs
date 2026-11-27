//! Store ordered policy statements and their operator audit atomically.
use super::*;
use crate::{grant_response::SessionOrigin, request_json::fields};

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let raw = match fields::document(&headers, &bytes) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let Some(raw) = raw else {
        return internal();
    };
    let policy = match policy_input::create(&raw) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if chain.is_some() {
        return crate::login_http::problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Blockchain policy creation unavailable",
        );
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    insert(tx, &policy, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn insert(
    mut tx: Transaction<'_, Postgres>,
    policy: &Value,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO iam_policies (id,name,description) VALUES ($1,$2,$3)")
        .bind(id)
        .bind(policy["name"].as_str())
        .bind(policy["description"].as_str())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO iam_policy_statements (id,policy_id,sort_order,sid,effect,actions,resources,conditions)
                 SELECT gen_random_uuid(),$1,ordinality-1,item->>'sid',item->>'effect',item->'actions',item->'resources',item->'conditions'
                 FROM jsonb_array_elements($2) WITH ORDINALITY AS entries(item,ordinality)")
        .bind(id).bind(&policy["statements"]).execute(&mut *tx).await?;
    let stored = statements::policies(&mut tx, Some(id))
        .await?
        .pop()
        .ok_or(sqlx::Error::RowNotFound)?;
    crate::admin_audit::append(
        &mut tx,
        "iam.policy.create",
        Some(actor),
        ("iam_policy", &id.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(stored)).into_response())
}
