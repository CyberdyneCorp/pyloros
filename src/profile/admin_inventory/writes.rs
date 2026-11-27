//! Store ordered policy statements and their operator audit atomically.
use super::*;
use crate::{grant_response::SessionOrigin, request_json::fields};

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    write(&state, peer, &headers, &bytes, None).await
}

pub(in crate::profile) async fn replace(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Path(path): axum::extract::Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    write(&state, peer, &headers, &bytes, Some(&path)).await
}

async fn write(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    bytes: &[u8],
    path: Option<&str>,
) -> Response {
    let raw = match fields::document(headers, bytes) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (tx, actor, email) = match administrator::operator(state, headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Ok(chain) = admin_client_roles::authority(state).await else {
        return internal();
    };
    let Some(raw) = raw else {
        return internal();
    };
    let path = path.map(|raw| crate::query::path_uuid(raw, "policy_id"));
    let (id, policy) = match policy_input::parse(&raw, path) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if let Some(chain) = chain {
        if tx.commit().await.is_err() {
            return internal();
        }
        if let Some(id) = id {
            return unavailable_chain_write(&chain, id, "Blockchain policy update unavailable")
                .await;
        }
        return crate::login_http::problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Blockchain policy creation unavailable",
        );
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    store(tx, id, &policy, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

pub(super) async fn unavailable_chain_write(
    chain: &crate::chain_settings::Chain,
    id: Uuid,
    detail: &str,
) -> Response {
    match chain.operator_policy(id).await {
        Ok(None) => missing(id),
        Err(error) => admin_client_roles::chain_error(error),
        Ok(Some(_)) => crate::login_http::problem(StatusCode::SERVICE_UNAVAILABLE, detail),
    }
}

pub(super) fn missing(id: Uuid) -> Response {
    crate::login_http::problem(StatusCode::NOT_FOUND, &format!("policy {id}"))
}

async fn store(
    mut tx: Transaction<'_, Postgres>,
    target: Option<Uuid>,
    policy: &Value,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let (id, status, action) = if let Some(id) = target {
        if !replace_metadata(&mut tx, id, policy).await? {
            return Ok(missing(id));
        }
        (id, StatusCode::OK, "iam.policy.update")
    } else {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO iam_policies (id,name,description) VALUES ($1,$2,$3)")
            .bind(id)
            .bind(policy["name"].as_str())
            .bind(policy["description"].as_str())
            .execute(&mut *tx)
            .await?;
        (id, StatusCode::CREATED, "iam.policy.create")
    };
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
        action,
        Some(actor),
        ("iam_policy", &id.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((status, Json(stored)).into_response())
}

async fn replace_metadata(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    policy: &Value,
) -> Result<bool, sqlx::Error> {
    let locked =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM iam_policies WHERE id=$1 FOR NO KEY UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?;
    if locked.is_none() {
        return Ok(false);
    }
    // Historical statements must be readable before a replacement can proceed.
    statements::policies(tx, Some(id)).await?;
    sqlx::query("UPDATE iam_policies SET name=COALESCE($2,name), description=COALESCE($3,description),version=version+1,updated_at=now() WHERE id=$1")
        .bind(id).bind(policy["name"].as_str()).bind(policy["description"].as_str()).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM iam_policy_statements WHERE policy_id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(true)
}
