//! Claim a Google Play subscription for the signed-in account.
use super::*;
use crate::{login_http::problem, request_json::fields};
use axum::body::Bytes;
pub(super) mod notifications;
mod provider;
mod push_identity;
pub(super) use provider::Provider;

#[derive(Debug)]
enum Failure {
    Invalid,
    Gone,
    Unavailable,
}

fn input(raw: &serde_json::value::RawValue) -> Result<(String, String), Box<Response>> {
    let submitted = fields::object_fields(raw)?;
    let projected = fields::project_scalars(raw, &submitted, &["purchase_token", "product_id"]);
    let body = admin_fields::object(&projected)
        .map_err(|issues| fields::invalid(issues.into_iter().map(|e| (e, raw)).collect()))?;
    let mut f = admin_fields::Fields {
        body,
        issues: vec![],
    };
    let token = f.string("purchase_token", Some(512), true);
    let product = f.string("product_id", Some(255), true);
    match (token, product) {
        (Some(t), Some(p)) if f.issues.is_empty() => Ok((t, p)),
        _ => Err(fields::invalid(
            f.issues
                .into_iter()
                .map(|e| {
                    let v = e["loc"][1]
                        .as_str()
                        .and_then(|k| submitted.get(k).copied())
                        .unwrap_or(raw);
                    (e, v)
                })
                .collect(),
        )),
    }
}

pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    if method != Method::POST {
        return passkeys::post_required();
    }
    let body = match fields::document(&headers, &bytes) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let Some(id) = credential(&headers).and_then(|v| state.verify.as_ref()?.read(v)) else {
        return unauthorized();
    };
    match authenticated_transaction(&state, &id).await {
        Ok(tx) => drop(tx),
        Err(e) => return *e,
    }
    let Some(raw) = body else { return internal() };
    let (token, product) = match input(&raw) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let Some(provider) = &state.google_play else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"billing not enabled"})),
        )
            .into_response();
    };
    claim(
        &state.pool,
        id.user,
        &token,
        &product,
        provider,
        state.registration.hooks,
    )
    .await
    .unwrap_or_else(|_| internal())
}
async fn claim(
    pool: &PgPool,
    user: Uuid,
    token: &str,
    store_product: &str,
    provider: &Provider,
    hooks: bool,
) -> sqlx::Result<Response> {
    let Ok(_slot) = provider.store_slots.acquire().await else {
        return Ok(internal());
    };
    let mut tx = pool.begin().await?;
    lock_purchase(&mut tx, token).await?;
    let expiry = match provider.expiry(token, store_product).await {
        Ok(t) => t,
        Err(Failure::Invalid | Failure::Gone) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid purchase"})),
            )
                .into_response());
        }
        Err(Failure::Unavailable) => return Ok(internal()),
    };

    let missing = || {
        problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unknown or unmapped Play product",
        )
    };
    let mapping = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT product_key,plan FROM google_products WHERE google_product_id=$1",
    )
    .bind(store_product)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((product, plan)) = mapping else {
        return Ok(missing());
    };
    let owner = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM google_purchases WHERE purchase_token=$1",
    )
    .bind(token)
    .fetch_optional(&mut *tx)
    .await?;
    if owner.is_some_and(|o| o != user) {
        return Ok(problem(
            StatusCode::CONFLICT,
            "Purchase already claimed by another account",
        ));
    }
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_one(&mut *tx)
        .await?;
    if !store_products::grantable(&mut tx, &product).await? {
        return Ok(missing());
    }
    if owner.is_none() {
        sqlx::query("INSERT INTO google_purchases(id,user_id,purchase_token) VALUES($1,$2,$3)")
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(token)
            .execute(&mut *tx)
            .await?;
    }
    let grant = billing_grants::Grant {
        product: &product,
        plan: plan.as_deref(),
        expires: Some(expiry),
        reference: Some(token),
        source: "google",
    };
    if !billing_grants::apply(&mut tx, user, grant, hooks).await? {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Entitlement hook dispatcher unavailable",
        ));
    }
    tx.commit().await?;
    let access = plan
        .filter(|p| !p.is_empty())
        .map_or_else(|| product.clone(), |p| format!("{product}:{p}"));
    Ok(Json(json!({"granted":true,"token":access,"expires_at":timestamp(expiry)})).into_response())
}

async fn lock_purchase(tx: &mut Transaction<'_, Postgres>, token: &str) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('google-purchase'),hashtext($1))")
        .bind(token)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
