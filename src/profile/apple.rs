//! Claim a StoreKit transaction for an authenticated customer.
use super::*;
use crate::{login_http::problem, request_json::fields};
use axum::body::Bytes;
pub(super) mod notifications;
mod ocsp;
mod verifier;

pub(super) struct Store {
    verifier: tokio::sync::OnceCell<verifier::Verifier>,
    roots: std::path::PathBuf,
    app_id: Option<u64>,
    bundle: String,
    environment: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Purchase {
    bundle_id: String,
    environment: String,
    transaction_id: String,
    original_transaction_id: String,
    product_id: String,
    signed_date: i64,
    expires_date: Option<i64>,
    revocation_date: Option<i64>,
    #[serde(rename = "type")]
    product_type: String,
}
impl Store {
    pub(super) fn configured() -> Result<Option<Self>, Box<dyn Error>> {
        if !config::flag("BILLING_ENABLED")? {
            return Ok(None);
        }
        let setting = |name| env::var(name).ok().filter(|v| !v.is_empty());
        let (Some(bundle), Some(roots)) =
            (setting("APPLE_BUNDLE_ID"), setting("APPLE_ROOT_CA_DIR"))
        else {
            return Ok(None);
        };
        let environment = setting("APPLE_ENVIRONMENT").unwrap_or_else(|| "Production".into());
        Ok(Some(Self {
            verifier: tokio::sync::OnceCell::new(),
            roots: roots.into(),
            app_id: setting("APPLE_APP_APPLE_ID").and_then(|s| s.parse().ok()),
            bundle,
            environment,
        }))
    }
}
impl Store {
    async fn verifier(&self) -> Result<&verifier::Verifier, ()> {
        if !matches!(self.environment.as_str(), "Sandbox" | "Production")
            || (self.environment == "Production" && self.app_id.is_none())
        {
            return Err(());
        }
        self.verifier
            .get_or_try_init(|| async {
                let roots = self.roots.clone();
                tokio::task::spawn_blocking(move || {
                    verifier::Verifier::load(&roots).map_err(|_| ())
                })
                .await
                .map_err(|_| ())?
            })
            .await
    }
}
impl Purchase {
    fn matches(&self, bundle: &str, environment: &str, now: DateTime<Utc>) -> bool {
        self.signed_date <= now.timestamp_millis().saturating_add(60000)
            && self.bundle_id == bundle
            && self.environment == environment
            && !self.original_transaction_id.is_empty()
            && !self.transaction_id.is_empty()
            && !self.product_id.is_empty()
    }

    fn expiry(
        &self,
        bundle: &str,
        environment: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>, verifier::Fault> {
        if !self.matches(bundle, environment, now) || self.revocation_date.is_some() {
            return Err(verifier::Fault::Invalid);
        }
        match self.expires_date {
            Some(raw) => DateTime::from_timestamp_millis(raw)
                .filter(|t| *t > now)
                .map(Some)
                .ok_or(verifier::Fault::Invalid),
            None if self.product_type == "Auto-Renewable Subscription" => {
                Err(verifier::Fault::Invalid)
            }
            None => Ok(None),
        }
    }
}

fn input(raw: &serde_json::value::RawValue) -> Result<String, Box<Response>> {
    let submitted = fields::object_fields(raw)?;
    let projected = fields::project_scalars(raw, &submitted, &["signed_transaction"]);
    let body = admin_fields::object(&projected)
        .map_err(|issues| fields::invalid(issues.into_iter().map(|e| (e, raw)).collect()))?;
    let mut f = admin_fields::Fields {
        body,
        issues: vec![],
    };
    let value = f.string("signed_transaction", None, true);
    if let Some(value) = value
        && f.issues.is_empty()
    {
        return Ok(value);
    }
    let field = submitted.get("signed_transaction").copied().unwrap_or(raw);
    Err(fields::invalid(
        f.issues.into_iter().map(|e| (e, field)).collect(),
    ))
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
        Ok(value) => value,
        Err(e) => return *e,
    };
    let Some(id) = credential(&headers).and_then(|v| state.verify.as_ref()?.read(v)) else {
        return unauthorized();
    };
    match authenticated_transaction(&state, &id).await {
        Ok(tx) => drop(tx),
        Err(e) => return *e,
    }
    let Some(raw) = body else {
        return internal();
    };
    let signed = match input(&raw) {
        Ok(s) => s,
        Err(e) => return *e,
    };
    let Some(store) = &state.apple else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"billing not enabled"})),
        )
            .into_response();
    };
    let invalid = || {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid signature"})),
        )
            .into_response()
    };
    let Ok(verifier) = store.verifier().await else {
        return internal();
    };
    let purchase: Purchase = match verifier.decode(&signed).await {
        Ok(p) => p,
        Err(verifier::Fault::Invalid) => return invalid(),
        Err(verifier::Fault::Unavailable) => {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let Ok(expiry) = purchase.expiry(&store.bundle, &store.environment, Utc::now()) else {
        return invalid();
    };
    claim(
        &state.pool,
        id.user,
        &purchase,
        expiry,
        state.registration.hooks,
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn claim(
    pool: &PgPool,
    user: Uuid,
    purchase: &Purchase,
    expiry: Option<DateTime<Utc>>,
    hooks: bool,
) -> sqlx::Result<Response> {
    let mut tx = pool.begin().await?;
    let reference = &purchase.original_transaction_id;
    lock_purchase(&mut tx, reference).await?;
    let missing = || {
        problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unknown or unmapped App Store product",
        )
    };
    let mapping = mapping(&mut tx, &purchase.product_id).await?;
    let Some((product, plan)) = mapping else {
        return Ok(missing());
    };
    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM apple_transactions WHERE original_transaction_id=$1",
    )
    .bind(reference)
    .fetch_optional(&mut *tx)
    .await?;
    if owner.is_some_and(|owner| owner != user) {
        return Ok(problem(
            StatusCode::CONFLICT,
            "Transaction already claimed by another account",
        ));
    }
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_one(&mut *tx)
        .await?;
    if !store_products::grantable(&mut tx, &product).await? {
        return Ok(missing());
    }
    if owner.is_some()
        && stale_purchase(
            &mut tx,
            user,
            reference,
            &product,
            plan.as_deref(),
            expiry,
            purchase.signed_date,
        )
        .await?
    {
        return Ok(problem(
            StatusCode::CONFLICT,
            "A newer entitlement change exists for this transaction",
        ));
    }
    if owner.is_none() {
        sqlx::query(
            "INSERT INTO apple_transactions(id,user_id,original_transaction_id) VALUES($1,$2,$3)",
        )
        .bind(Uuid::new_v4())
        .bind(user)
        .bind(reference)
        .execute(&mut *tx)
        .await?;
    }
    let grant = billing_grants::Grant {
        product: &product,
        plan: plan.as_deref(),
        source: "apple",
        reference: Some(reference),
        expires: expiry,
    };
    if !billing_grants::apply(&mut tx, user, grant, hooks).await? {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Entitlement hook dispatcher unavailable",
        ));
    }
    tx.commit().await?;
    let token = plan
        .filter(|p| !p.is_empty())
        .map_or_else(|| product.clone(), |p| format!("{product}:{p}"));
    Ok(
        Json(json!({"granted":true,"token":token,"expires_at":expiry.map(timestamp)}))
            .into_response(),
    )
}

async fn lock_purchase(tx: &mut Transaction<'_, Postgres>, reference: &str) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('apple-purchase'),hashtext($1))")
        .bind(reference)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn mapping(
    tx: &mut Transaction<'_, Postgres>,
    store_id: &str,
) -> sqlx::Result<Option<(String, Option<String>)>> {
    sqlx::query_as("SELECT product_key,plan FROM apple_products WHERE app_store_product_id=$1")
        .bind(store_id)
        .fetch_optional(&mut **tx)
        .await
}
async fn stale_purchase(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    reference: &str,
    product: &str,
    plan: Option<&str>,
    expiry: Option<DateTime<Utc>>,
    signed: i64,
) -> sqlx::Result<bool> {
    let Some(signed) = DateTime::from_timestamp_millis(signed) else {
        return Ok(true);
    };
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM entitlements WHERE user_id=$1 AND source='apple' AND external_ref=$2 AND
        ((status='revoked' AND product_key=$3 AND plan IS NOT DISTINCT FROM $4 AND revoked_at >= $6)
        OR (status='active' AND (product_key,plan) IS DISTINCT FROM ($3::text,$4::text) AND updated_at >= $6)
        OR (status='active' AND product_key=$3 AND plan IS NOT DISTINCT FROM $4 AND expires_at > $5)))")
        .bind(user).bind(reference).bind(product).bind(plan).bind(expiry).bind(signed).fetch_one(&mut **tx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn stale_receipts_preserve_revocations_and_newer_renewals() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE entitlements(user_id uuid,source text,external_ref text,status text,product_key text,plan text,revoked_at timestamptz,updated_at timestamptz,expires_at timestamptz)").execute(&mut *tx).await.unwrap();
        let user = Uuid::new_v4();
        let now = Utc::now();
        let expiry = now + chrono::Duration::days(10);
        sqlx::query("INSERT INTO entitlements VALUES($1,'apple','receipt','revoked','app','monthly',$2,$2,$3)").bind(user).bind(now).bind(expiry).execute(&mut *tx).await.unwrap();
        assert!(
            stale_purchase(
                &mut tx,
                user,
                "receipt",
                "app",
                Some("monthly"),
                Some(expiry),
                now.timestamp_millis()
            )
            .await
            .unwrap()
        );
        sqlx::query("UPDATE entitlements SET status='active',revoked_at=NULL")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(
            stale_purchase(
                &mut tx,
                user,
                "receipt",
                "app",
                Some("monthly"),
                Some(now),
                now.timestamp_millis()
            )
            .await
            .unwrap()
        );
        assert!(
            !stale_purchase(
                &mut tx,
                user,
                "receipt",
                "app",
                Some("monthly"),
                Some(expiry),
                now.timestamp_millis()
            )
            .await
            .unwrap()
        );
    }
}
