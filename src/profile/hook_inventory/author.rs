//! Save hook definitions and their operator audit entries atomically.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem, request_json::iam_document};
use axum::body::Bytes;

pub(super) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    write(&state, peer, &headers, &bytes, None).await
}
pub(super) async fn update(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    write(&state, peer, &headers, &bytes, Some(&path)).await
}
pub(super) async fn update_reserved(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    write(&state, peer, &headers, &bytes, Some("validate")).await
}

async fn write(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    bytes: &[u8],
    path: Option<&str>,
) -> Response {
    let raw = match iam_document::document(headers, bytes) {
        Ok(raw) => raw,
        Err(e) => return *e,
    };
    let (tx, actor, email) = match administrator::operator(state, headers).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let Some(raw) = raw else { return internal() };
    let (id, patch) = match input::parse(&raw, path) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    store(tx, id, &patch, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

fn conflict() -> Response {
    problem(StatusCode::CONFLICT, "Hook name already in use")
}

async fn store(
    mut tx: Transaction<'_, Postgres>,
    target: Option<Uuid>,
    patch: &Value,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> sqlx::Result<Response> {
    let current = if let Some(id) = target {
        let sql = format!("SELECT {FIELDS} FROM hooks WHERE id=$1 FOR UPDATE");
        let Some(row) = sqlx::query(&sql).bind(id).fetch_optional(&mut *tx).await? else {
            return Ok(missing());
        };
        Some(hook(&row)?)
    } else {
        None
    };
    let id = target.unwrap_or_else(Uuid::new_v4);
    if let Some(name) = patch["name"].as_str() {
        let taken: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM hooks WHERE name=$1 AND id<>$2)")
                .bind(name)
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        if taken {
            return Ok(conflict());
        }
    }
    if let Some(code) = patch["code"].as_str() {
        match wasm_hooks::inspect_source(code).await {
            Ok(None) => (),
            Ok(Some(reason)) => return Ok(problem(StatusCode::BAD_REQUEST, &reason)),
            Err(e) => return Ok(*e),
        }
    }
    let definition = persist(&mut tx, id, current, patch).await?;
    let (action, status, metadata) = match target {
        Some(_) => {
            let mut fields: Vec<_> = patch.as_object().expect("parsed patch").keys().collect();
            fields.sort_unstable();
            (
                "hook.update",
                StatusCode::OK,
                json!({"name":definition["name"],"changed_fields":fields}),
            )
        }
        None => (
            "hook.create",
            StatusCode::CREATED,
            json!({"name":definition["name"],"event_type":definition["event_type"]}),
        ),
    };
    crate::admin_audit::append(
        &mut tx,
        action,
        Some(actor),
        ("hook", &id.to_string()),
        metadata,
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((status, Json(definition)).into_response())
}

async fn persist(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    current: Option<Value>,
    patch: &Value,
) -> sqlx::Result<Value> {
    let creating = current.is_none();
    let mut definition = current.unwrap_or_else(
        || json!({"is_active":true,"timeout_seconds":5,"allow_network":false,"receive_pii":false}),
    );
    let mut changed = false;
    for (field, value) in patch.as_object().expect("parsed patch") {
        changed |= definition[field] != *value;
        definition[field] = value.clone();
    }
    if !creating && !changed {
        return Ok(definition);
    }
    let statement = if creating {
        "INSERT INTO hooks(id,name,event_type,code,is_active,timeout_seconds,allow_network,receive_pii) VALUES($1,$2,$3,$4,$5,$6,$7,$8)"
    } else {
        "UPDATE hooks SET name=$2,event_type=$3,code=$4,is_active=$5,timeout_seconds=$6,allow_network=$7,receive_pii=$8,updated_at=now() WHERE id=$1"
    };
    let sql = format!("{statement} RETURNING {FIELDS}");
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(definition["name"].as_str())
        .bind(definition["event_type"].as_str())
        .bind(definition["code"].as_str())
        .bind(definition["is_active"].as_bool())
        .bind(definition["timeout_seconds"].as_i64().map(|n| n as i32))
        .bind(definition["allow_network"].as_bool())
        .bind(definition["receive_pii"].as_bool())
        .fetch_one(&mut **tx)
        .await?;
    hook(&row)
}
