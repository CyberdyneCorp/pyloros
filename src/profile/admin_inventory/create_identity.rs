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
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    store(tx, chain, request, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn store(
    mut tx: Transaction<'_, Postgres>,
    chain: Option<crate::chain_settings::Chain>,
    mut request: Request,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let (id, chain_token_id) = if let Some(chain) = chain {
        chain.lock_signer(&mut tx).await?;
        let Ok((id, token)) = chain
            .create_identity(
                request.owner_address.as_deref().unwrap_or_default(),
                request.public_key.as_deref().unwrap_or_default(),
                request.metadata_uri.as_deref().unwrap_or_default(),
            )
            .await
        else {
            return Ok(problem(
                StatusCode::NOT_FOUND,
                "identity mint failed on chain",
            ));
        };
        request.user_id = None;
        (id, Some(token))
    } else {
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
        (id, None)
    };
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
    Ok((
        StatusCode::CREATED,
        Json(CreatedIdentity {
            id,
            chain_token_id,
            request,
            created_at: (),
        }),
    )
        .into_response())
}

#[derive(Serialize)]
struct CreatedIdentity {
    id: Uuid,
    chain_token_id: Option<Box<serde_json::value::RawValue>>,
    #[serde(flatten)]
    request: Request,
    created_at: (),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_identity_preserves_full_width_chain_ids_and_nullable_fields() {
        let digits = alloy_primitives::U256::MAX.to_string();
        let identity = CreatedIdentity {
            id: Uuid::nil(),
            chain_token_id: Some(serde_json::value::RawValue::from_string(digits.clone()).unwrap()),
            request: Request {
                user_id: None,
                owner_address: None,
                public_key: None,
                email: None,
                metadata_uri: None,
                status: "active".into(),
                transfer_mode: "soulbound".into(),
            },
            created_at: (),
        };
        let wire = serde_json::to_string(&identity).unwrap();
        let fields: std::collections::HashMap<&str, &serde_json::value::RawValue> =
            serde_json::from_str(&wire).unwrap();
        assert_eq!(fields["chain_token_id"].get(), digits);
        assert_eq!(fields["user_id"].get(), "null");
        assert_eq!(fields["created_at"].get(), "null");
    }
}
