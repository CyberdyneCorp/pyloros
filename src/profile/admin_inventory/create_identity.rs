//! Provision an identity and record the operator who created it.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem, request_json::iam_document};
use serde::Deserialize;

#[derive(Deserialize, Serialize)]
pub(super) struct Request {
    user_id: Option<Uuid>,
    owner_address: Option<String>,
    public_key: Option<String>,
    email: Option<String>,
    metadata_uri: Option<String>,
    status: String,
    transfer_mode: String,
}

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let raw = match iam_document::document(&headers, &bytes) {
        Ok(raw) => raw,
        Err(error) => return *error,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(record) => record,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let Some(raw) = raw else {
        return internal();
    };
    let request = match input::identity(&raw) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    if user_identity::validate_identity(&request.status, &request.transfer_mode).is_err() {
        return internal();
    }
    if let Some(chain) = chain {
        if tx.commit().await.is_err() {
            return internal();
        }
        let prepared = chain
            .prepare_identity_creation(
                request.owner_address.as_deref().unwrap_or_default(),
                request.public_key.as_deref().unwrap_or_default(),
                request.metadata_uri.as_deref().unwrap_or_default(),
            )
            .await;
        return match prepared {
            Ok(_) => problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Blockchain transaction submission unavailable",
            ),
            Err(_) => problem(StatusCode::NOT_FOUND, "identity mint failed on chain"),
        };
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    store(tx, request, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn store(
    mut tx: Transaction<'_, Postgres>,
    request: Request,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    if let Some(user) = request.user_id
        && user_identity::details(&mut tx, user_identity::Lookup::User(user))
            .await?
            .is_some()
    {
        return Ok(problem(
            StatusCode::CONFLICT,
            &format!("user {user} already has a linked IAM identity"),
        ));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO iam_identities(id,user_id,owner_address,public_key,email,metadata_uri,status,transfer_mode)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id).bind(request.user_id).bind(&request.owner_address).bind(&request.public_key)
        .bind(&request.email).bind(&request.metadata_uri).bind(&request.status).bind(&request.transfer_mode)
        .execute(&mut *tx).await?;
    crate::admin_audit::append(
        &mut tx,
        "iam.identity.create",
        Some(actor),
        ("iam_identity", &id.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    let mut identity = json!(request);
    identity["id"] = json!(id);
    identity["created_at"] = Value::Null;
    identity["chain_token_id"] = Value::Null;
    Ok((StatusCode::CREATED, Json(identity)).into_response())
}
