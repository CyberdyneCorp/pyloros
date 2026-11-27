//! Atomic partial changes to administrator-managed and self-registered clients.
use super::*;
use crate::{
    browser_prompt::quoted_list,
    token_runtime::{ResourceRegistry, resource_registry},
};
use serde_json::Map;

pub(in crate::profile) async fn update(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(target): Path<String>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let data = match body(&headers, &bytes) {
        Ok(data) => data,
        Err(r) => return *r,
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: header_value(&headers, "user-agent"),
    };
    handle(&state, &headers, Operation::Patch(&target, data, origin)).await
}

pub(super) async fn init_resources(state: &Profile) -> Result<(), Box<dyn Error>> {
    let seconds = crate::token_runtime::number("OAUTH_REGISTRY_REFRESH_SECONDS", 30)?.try_into()?;
    let base = ResourceRegistry::from_env()?;
    state
        .patch_resources
        .get_or_init(|| resource_registry(state.pool.clone(), base, seconds))
        .await;
    Ok(())
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn added_outside(previous: &Value, next: &Value, allowed: &BTreeSet<&str>) -> Option<String> {
    let previous = strings(previous);
    let next = strings(next);
    let extra: Vec<_> = next
        .difference(&previous)
        .map(String::as_str)
        .filter(|s| !allowed.contains(s))
        .collect();
    (!extra.is_empty()).then(|| quoted_list(&extra))
}
fn dynamic_limits(
    old: &Value,
    patch: &Map<String, Value>,
    resources: &ResourceRegistry,
) -> Result<(), String> {
    if patch.get("client_type") == Some(&json!("confidential"))
        && old["client_type"] != "confidential"
    {
        return Err("a dynamically registered client must stay public".into());
    }
    if let Some(extra) = patch.get("grant_types").and_then(|g| {
        added_outside(
            &old["grant_types"],
            g,
            &["authorization_code", "refresh_token"].into(),
        )
    }) {
        return Err(format!(
            "a dynamically registered client may only use the authorization_code and refresh_token grants: {extra}"
        ));
    }
    if let Some(extra) = patch
        .get("allowed_scopes")
        .and_then(|s| added_outside(&old["allowed_scopes"], s, &resources.registration_scopes()))
    {
        return Err(format!(
            "scopes beyond the dynamic-registration ceiling: {extra}"
        ));
    }
    Ok(())
}

fn merge(old: &Value, patch: &Map<String, Value>) -> Value {
    let mut new = old.clone();
    for (field, value) in patch {
        if !value.is_null() {
            new[field] = value.clone();
            continue;
        }
        match field.as_str() {
            "allowed_scopes" => new[field] = json!([]),
            "allowed_audiences"
            | "redirect_uris"
            | "post_logout_redirect_uris"
            | "access_token_audience" => new[field] = Value::Null,
            _ => {}
        }
    }
    new
}
fn validate(
    state: &Profile,
    old: &Value,
    patch: &Map<String, Value>,
    new: &Value,
) -> Result<(), String> {
    let dynamic = old["registration_source"] == "dynamic";
    if dynamic {
        let resources = state
            .patch_resources
            .get()
            .ok_or("Resource registry unavailable")?;
        dynamic_limits(old, patch, &resources.borrow())?;
    }
    if patch.contains_key("allowed_scopes") {
        let scopes = state
            .client_scopes
            .get()
            .ok_or("Scope catalog unavailable")?;
        creation::validate_scopes(&strings(&new["allowed_scopes"]), &scopes.borrow())?;
    }
    let grants = strings(&new["grant_types"]);
    if patch.get("grant_types").is_some_and(|g| !g.is_null()) {
        creation::validate_grants(&grants)?;
        if dynamic && grants.contains("urn:ietf:params:oauth:grant-type:device_code") {
            return Err("a dynamically registered client cannot use the device_code grant".into());
        }
    }
    if patch.contains_key("access_token_audience") {
        creation::validate_audience(new["access_token_audience"].as_str())?;
    }
    if dynamic && patch.get("trusted") == Some(&Value::Bool(true)) {
        return Err("a dynamically registered client cannot be trusted".into());
    }
    let kind = new["client_type"].as_str().unwrap_or("");
    creation::redirects(
        kind,
        grants.contains("authorization_code"),
        Some(&strings(&new["redirect_uris"])),
        Some(&strings(&new["post_logout_redirect_uris"])),
        patch.contains_key("redirect_uris"),
    )
}

async fn persist(
    tx: &mut Transaction<'_, Postgres>,
    target: &str,
    mut new: Value,
) -> Result<Option<Value>, sqlx::Error> {
    for field in ["allowed_scopes", "grant_types"] {
        new[field] = json!(
            strings(&new[field])
                .into_iter()
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    // Leave credential hashes and grant activity to their respective writers.
    let statement = format!(
        "WITH desired AS (
            SELECT r.name, r.description, r.allowed_scopes,
                   coalesce(r.allowed_audiences, CASE WHEN c.allowed_audiences IS NOT NULL THEN 'null'::jsonb END),
                   r.max_token_ttl_s, r.active, r.grant_types, r.client_type,
                   coalesce(r.redirect_uris, CASE WHEN c.redirect_uris IS NOT NULL THEN 'null'::jsonb END),
                   coalesce(r.post_logout_redirect_uris, CASE WHEN c.post_logout_redirect_uris IS NOT NULL THEN 'null'::jsonb END),
                   r.access_token_audience, r.trusted
              FROM oauth_clients c CROSS JOIN jsonb_populate_record(NULL::oauth_clients, $2) r
             WHERE c.client_id = $1
        )
        UPDATE oauth_clients c SET
           (name, description, allowed_scopes, allowed_audiences, max_token_ttl_s, active, grant_types,
            client_type, redirect_uris, post_logout_redirect_uris, access_token_audience, trusted) =
            (SELECT * FROM desired),
            updated_at = now()
         WHERE c.client_id = $1 AND
            (c.name, c.description, c.allowed_scopes, c.allowed_audiences, c.max_token_ttl_s, c.active,
             c.grant_types, c.client_type, c.redirect_uris, c.post_logout_redirect_uris,
             c.access_token_audience, c.trusted) IS DISTINCT FROM (SELECT d FROM desired d)
         RETURNING {COLUMNS}"
    );
    let row = sqlx::query(&statement)
        .bind(target)
        .bind(new)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(item).transpose()
}

pub(super) async fn apply(
    state: &Profile,
    mut tx: Transaction<'_, Postgres>,
    actor: (Uuid, Option<&str>),
    target: &str,
    body: Option<Value>,
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let Some(body) = body else {
        return Ok(internal());
    };
    let patch = match metadata::patch_fields(&body) {
        Ok(p) => p,
        Err(issues) => {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":issues})),
            )
                .into_response());
        }
    };
    let row = sqlx::query(&format!(
        "SELECT {COLUMNS} FROM oauth_clients WHERE client_id=$1 FOR UPDATE"
    ))
    .bind(target)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Ok(problem(StatusCode::NOT_FOUND, "OAuth client not found"));
    };
    let old = item(row)?;
    let new = merge(&old, &patch);
    if let Err(message) = validate(state, &old, &patch, &new) {
        return Ok(problem(StatusCode::BAD_REQUEST, &message));
    }
    let changed = persist(&mut tx, target, new).await?.unwrap_or(old);
    let fields: BTreeSet<_> = patch.keys().collect();
    crate::admin_audit::append_client_action(
        &mut tx,
        "oauth_client.update",
        Some(actor),
        target,
        json!({"changed_fields":fields}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(changed).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn clearing_a_list_preserves_the_reference_null_encoding_and_no_op_timestamp() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE oauth_clients (
            id uuid, client_id text, name text, description text, secret_hash text,
            allowed_scopes text, allowed_audiences jsonb, max_token_ttl_s int DEFAULT 3600,
            active bool DEFAULT true, grant_types text DEFAULT 'client_credentials',
            client_type text DEFAULT 'confidential', redirect_uris jsonb, post_logout_redirect_uris jsonb,
            access_token_audience text, trusted bool DEFAULT false, registration_source text DEFAULT 'admin',
            created_by_user_id uuid, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now(),
            last_used_at timestamptz) ON COMMIT DROP").execute(&mut *tx).await.unwrap();
        let row=sqlx::query(&format!("INSERT INTO oauth_clients(id,client_id,name,secret_hash,allowed_scopes,allowed_audiences,redirect_uris) VALUES ($1,'client','Client','test','','[\"before\"]',NULL) RETURNING {COLUMNS}")).bind(Uuid::new_v4()).fetch_one(&mut *tx).await.unwrap();
        let mut new = item(row).unwrap();
        new["allowed_audiences"] = Value::Null;
        assert!(
            persist(&mut tx, "client", new.clone())
                .await
                .unwrap()
                .is_some()
        );
        let encodings:(Option<String>,Option<String>)=sqlx::query_as("SELECT allowed_audiences::text,redirect_uris::text FROM oauth_clients WHERE client_id='client'").fetch_one(&mut *tx).await.unwrap();
        assert_eq!(encodings, (Some("null".into()), None));
        assert!(persist(&mut tx, "client", new).await.unwrap().is_none());
    }
}
