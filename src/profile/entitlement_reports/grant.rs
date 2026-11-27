//! Issue or reactivate a product entitlement for one owner.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem, request_json::fields};
use wasm_hooks::delivery::{Entitlement, Producer};
mod input;

struct Grant {
    user: Option<Uuid>,
    org: Option<Uuid>,
    product: String,
    plan: Option<String>,
    expires: Option<datetime::ParsedDateTime>,
}

pub(super) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let raw = match fields::document(&headers, &bytes) {
        Ok(raw) => raw,
        Err(e) => return *e,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(op) => op,
        Err(e) => return *e,
    };
    let Some(raw) = raw else { return internal() };
    let grant = match fields::validate_scalar_document(&raw, input::KEYS, input::parse) {
        Ok(g) => g,
        Err(e) => return *e,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    write(
        tx,
        grant,
        actor,
        email.as_deref(),
        origin,
        state.registration.hooks,
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn validate(tx: &mut Transaction<'_, Postgres>, g: &Grant) -> sqlx::Result<Option<Response>> {
    let (id, query, message) = match (g.user, g.org) {
        (Some(id), None) => (
            id,
            "SELECT extra_metadata::text FROM users WHERE id=$1",
            "User not found",
        ),
        (None, Some(id)) => (
            id,
            "SELECT extra_metadata::text FROM organizations WHERE id=$1",
            "Organization not found",
        ),
        _ => {
            return Ok(Some(problem(
                StatusCode::BAD_REQUEST,
                "Provide exactly one of user_id or organization_id",
            )));
        }
    };
    let meta = sqlx::query_scalar::<_, String>(query)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(meta) = meta else {
        return Ok(Some(problem(StatusCode::NOT_FOUND, message)));
    };
    administrator::validate_metadata(&meta)?;
    if !store_products::grantable(tx, &g.product).await? {
        return Ok(Some(problem(
            StatusCode::BAD_REQUEST,
            "Unknown or inactive product",
        )));
    }
    Ok(None)
}

async fn write(
    mut tx: Transaction<'_, Postgres>,
    g: Grant,
    actor: Uuid,
    email: Option<&str>,
    origin: SessionOrigin<'_>,
    hooks: bool,
) -> sqlx::Result<Response> {
    if let Some(e) = validate(&mut tx, &g).await? {
        return Ok(e);
    }
    let (row, created) = save(&mut tx, &g, actor).await?;
    let id: Uuid = row.try_get("id")?;
    let entitlement = Entitlement {
        id,
        user: g.user,
        product: &g.product,
        plan: g.plan.as_deref(),
    };
    if hooks
        && !entitlement
            .granted(&mut tx, Producer::Administrator, g.org, "admin")
            .await?
    {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Entitlement grant hook dispatcher unavailable",
        ));
    }
    let item = item(&row, &Labels::new(), &Labels::new())?;
    let metadata = json!({
        "user_id": g.user, "organization_id": g.org, "product_key": g.product,
        "plan": g.plan, "created": created
    });
    crate::admin_audit::append(
        &mut tx,
        "entitlement_granted",
        Some((actor, email)),
        ("entitlement", &id.to_string()),
        metadata,
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(item)).into_response())
}

async fn save(
    tx: &mut Transaction<'_, Postgres>,
    g: &Grant,
    actor: Uuid,
) -> sqlx::Result<(PgRow, bool)> {
    if let Some(expiry) = &g.expires {
        expiry.check_utc_year()?;
    }
    let expires = g.expires.as_ref().map(|v| v.utc);
    let rows = sqlx::query(
        "SELECT *, extra_metadata::text AS metadata FROM entitlements
         WHERE (user_id=$1 OR organization_id=$2) AND product_key=$3
         AND plan IS NOT DISTINCT FROM $4 LIMIT 2",
    )
    .bind(g.user)
    .bind(g.org)
    .bind(&g.product)
    .bind(&g.plan)
    .fetch_all(&mut **tx)
    .await?;
    let mut rows = rows.into_iter();
    let Some(row) = rows.next() else {
        let inserted = sqlx::query(
            "INSERT INTO entitlements
             (id,user_id,organization_id,product_key,plan,expires_at,granted_by_user_id)
             VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *,extra_metadata::text AS metadata",
        )
        .bind(Uuid::new_v4())
        .bind(g.user)
        .bind(g.org)
        .bind(&g.product)
        .bind(&g.plan)
        .bind(expires)
        .bind(actor)
        .fetch_one(&mut **tx)
        .await?;
        return Ok((inserted, true));
    };
    if rows.next().is_some() {
        return Err(sqlx::Error::Protocol(
            "multiple grants match owner, product and plan".into(),
        ));
    }
    let (status, source) = stored_fields(&row)?;
    let metadata = normalized_storage(row.try_get("metadata")?)?;
    if status == "active"
        && source == "admin"
        && row.try_get::<Option<Uuid>, _>("granted_by_user_id")? == Some(actor)
        && row.try_get::<Option<DateTime<Utc>>, _>("expires_at")? == expires
        && !g.expires.as_ref().is_some_and(|v| v.local)
        && row
            .try_get::<Option<DateTime<Utc>>, _>("revoked_at")?
            .is_none()
        && metadata.is_none()
    {
        return Ok((row, false));
    }
    let updated = sqlx::query(
        "UPDATE entitlements SET status='active',source='admin',expires_at=$2,
         granted_by_user_id=$3,revoked_at=NULL,extra_metadata=coalesce($4::text::jsonb,extra_metadata),
         updated_at=now() WHERE id=$1 RETURNING *,extra_metadata::text AS metadata",
    )
    .bind(row.try_get::<Uuid, _>("id")?)
    .bind(expires)
    .bind(actor)
    .bind(metadata)
    .fetch_one(&mut **tx)
    .await?;
    Ok((updated, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn restoration_preserves_receipt_and_keeps_empty_plan_separate() -> sqlx::Result<()> {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::query(
            "CREATE TEMP TABLE entitlements (
              id uuid PRIMARY KEY, user_id uuid, organization_id uuid, product_key text, plan text,
              status text DEFAULT 'active', source text DEFAULT 'admin', external_ref text,
              expires_at timestamptz, revoked_at timestamptz, granted_by_user_id uuid,
              extra_metadata jsonb DEFAULT '{}', updated_at timestamptz DEFAULT now())",
        )
        .execute(&mut *tx)
        .await?;
        let actor = Uuid::new_v4();
        let mut grant = Grant {
            user: None,
            org: Some(Uuid::new_v4()),
            product: "test".into(),
            plan: None,
            expires: None,
        };
        let (first, created) = save(&mut tx, &grant, actor).await?;
        assert!(created);
        let id: Uuid = first.try_get("id")?;
        sqlx::query(
            "UPDATE entitlements SET source='stripe', status='revoked', revoked_at=now(),
                     external_ref='receipt', extra_metadata='[[\"quantity\",3]]' WHERE id=$1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        let (restored, created) = save(&mut tx, &grant, actor).await?;
        assert!(!created);
        assert_eq!(restored.try_get::<Uuid, _>("id")?, id);
        assert_eq!(restored.try_get::<&str, _>("external_ref")?, "receipt");
        assert_eq!(restored.try_get::<&str, _>("status")?, "active");
        assert_eq!(restored.try_get::<&str, _>("source")?, "admin");
        assert_eq!(
            restored.try_get::<Value, _>("extra_metadata")?,
            json!({"quantity":3})
        );
        assert!(
            restored
                .try_get::<Option<DateTime<Utc>>, _>("revoked_at")?
                .is_none()
        );
        grant.plan = Some(String::new());
        assert!(save(&mut tx, &grant, actor).await?.1);
        Ok(())
    }
}
