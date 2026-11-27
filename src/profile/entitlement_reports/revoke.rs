//! Retain the grant history when an operator withdraws access.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem};
use axum::extract::Path;
use wasm_hooks::delivery::{Entitlement, Producer};

pub(super) async fn remove(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::DELETE {
        let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
        return r;
    }
    handle(&state, &headers, peer, &raw).await
}

// A DELETE to the report name matches the grant identifier route in the REST API.
pub(super) async fn stats_path(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    handle(&state, &headers, peer, "stats").await
}

async fn handle(state: &Profile, headers: &HeaderMap, peer: SocketAddr, raw: &str) -> Response {
    let (tx, user, email) = match administrator::operator(state, headers).await {
        Ok(actor) => actor,
        Err(e) => return *e,
    };
    let id = match crate::query::path_uuid(raw, "entitlement_id") {
        Ok(id) => id,
        Err(e) => return passkeys::validation(vec![e]),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    withdraw(tx, id, (user, email), origin, state.registration.hooks)
        .await
        .unwrap_or_else(|_| internal())
}

async fn withdraw(
    mut tx: Transaction<'_, Postgres>,
    id: Uuid,
    (actor, email): (Uuid, Option<String>),
    origin: SessionOrigin<'_>,
    hooks: bool,
) -> sqlx::Result<Response> {
    let row=sqlx::query("SELECT user_id,organization_id,product_key,plan,status,source,extra_metadata::text AS metadata FROM entitlements WHERE id=$1")
        .bind(id).fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        return Ok(problem(StatusCode::NOT_FOUND, "Entitlement not found"));
    };
    stored_fields(&row)?;
    let metadata = normalized_storage(row.try_get("metadata")?)?;
    let entitlement = Entitlement {
        id,
        user: row.try_get("user_id")?,
        product: row.try_get("product_key")?,
        plan: row.try_get("plan")?,
    };
    if hooks
        && !entitlement
            .revoked(&mut tx, Producer::Administrator)
            .await?
    {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Entitlement revocation hook dispatcher unavailable",
        ));
    }
    let audit = json!({"user_id":entitlement.user,
        "organization_id":row.try_get::<Option<Uuid>,_>("organization_id")?,
        "product_key":entitlement.product});
    sqlx::query_scalar::<_, Uuid>(
        "UPDATE entitlements SET status='revoked',revoked_at=$2,updated_at=now(),
        extra_metadata=coalesce($3::text::jsonb,extra_metadata) WHERE id=$1 RETURNING id",
    )
    .bind(id)
    .bind(Utc::now())
    .bind(metadata)
    .fetch_one(&mut *tx)
    .await?;
    crate::admin_audit::append(
        &mut tx,
        "entitlement_revoked",
        Some((actor, email.as_deref())),
        ("entitlement", &id.to_string()),
        audit,
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
