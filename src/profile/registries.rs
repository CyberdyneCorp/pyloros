//! Administrative OAuth policy registries.
use super::*;
use crate::login_http::problem;
use axum::extract::{Path, RawQuery};
use std::collections::BTreeMap;

pub(super) fn configured_scopes() -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let mut scopes: BTreeMap<_, _> = [
        ("openid", "OpenID Connect identity"),
        ("profile", "Profile claims"),
        ("email", "Email claims"),
        ("offline_access", "Offline access"),
        ("roles", "Application roles"),
        ("users:provision", "Provision users"),
        ("directory:read", "Read the user directory"),
        ("roles:read", "Read roles"),
        ("roles:manage", "Manage roles"),
        ("iam:read.tier", "Read IAM tier"),
        ("admin:users.read", "Read users"),
        ("admin:users.write", "Manage users"),
        ("admin:sessions.read", "Read sessions"),
        ("admin:sessions.write", "Manage sessions"),
        ("admin:hooks.read", "Read hooks"),
        ("admin:hooks.write", "Manage hooks"),
    ]
    .into_iter()
    .map(|(k, v)| (String::from(k), String::from(v)))
    .collect();
    for name in env::var("PYLOROS_RESOURCE_SCOPE_CATALOG")
        .unwrap_or_default()
        .split_whitespace()
    {
        scopes.entry(name.to_owned()).or_default();
    }
    if let Some(path) = env::var_os("PYLOROS_CONSENT_UI_PATH") {
        #[derive(Deserialize)]
        struct Descriptions {
            descriptions: BTreeMap<String, String>,
        }
        let source: Descriptions = serde_json::from_slice(&std::fs::read(path)?)?;
        for (name, description) in source.descriptions {
            if let Some(existing) = scopes.get_mut(&name) {
                *existing = description;
            }
        }
    }
    Ok(scopes)
}

pub(super) async fn catalog(
    state: &Profile,
) -> Result<&crate::discovery::ScopeRegistry, Box<dyn Error>> {
    state
        .client_scopes
        .get_or_try_init(|| async {
            let seconds =
                crate::token_runtime::number("OAUTH_REGISTRY_REFRESH_SECONDS", 30)?.try_into()?;
            Ok(crate::discovery::ScopeRegistry::start(
                state.pool.clone(),
                state.builtin_scopes.clone(),
                None,
                Some(state.configured_resources.clone()),
                None,
                std::time::Duration::from_secs(seconds),
            )
            .await)
        })
        .await
}

mod deactivate;
mod mutation;
pub(super) mod origins;
mod resources;
pub(super) use deactivate::{origin as deactivate_origin, resource as deactivate_resource};
pub(super) use mutation::{create, deactivate, update};
pub(super) use resources::write::{create as create_resource, update as update_resource};

pub(super) async fn list_scopes(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    read(
        &state,
        method,
        &headers,
        Inventory::Scopes(query.as_deref().unwrap_or("")),
    )
    .await
}
pub(super) async fn get_scope(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    read(&state, method, &headers, Inventory::Scope(&name)).await
}
pub(super) async fn list_resources(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    read(&state, method, &headers, Inventory::Resources).await
}
pub(super) async fn get_resource(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    read(&state, method, &headers, Inventory::Resource(&id)).await
}
pub(super) async fn list_origins(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    read(&state, method, &headers, Inventory::Origins).await
}
pub(super) async fn get_origin(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    read(&state, method, &headers, Inventory::Origin(&id)).await
}
enum Inventory<'a> {
    Scopes(&'a str),
    Scope(&'a str),
    Resources,
    Resource(&'a str),
    Origins,
    Origin(&'a str),
}
async fn read(state: &Profile, method: Method, headers: &HeaderMap, op: Inventory<'_>) -> Response {
    if method != Method::GET {
        let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(header::ALLOW, "GET".parse().unwrap());
        return r;
    }
    let Some(id) = administrator::identity(state, headers) else {
        return unauthorized();
    };
    let (mut tx, _) = match administrator::session(state, &id).await {
        Ok(session) => session,
        Err(r) => return *r,
    };
    match op {
        Inventory::Origins => origins::list(&mut tx, &state.configured_origins).await,
        Inventory::Origin(id) => origins::get(&mut tx, id).await,
        Inventory::Resources => resources::list(&mut tx, &state.configured_resources).await,
        Inventory::Resource(id) => resources::get(&mut tx, id).await,
        Inventory::Scope(name) => get(&mut tx, &state.builtin_scopes, name).await,
        Inventory::Scopes(query) => list(&mut tx, &state.builtin_scopes, query).await,
    }
    .unwrap_or_else(|_| internal())
}

fn builtin(name: &str, description: &str) -> Value {
    json!({"name":name,"description":description,"source":"builtin","active":true,"created_at":null,"updated_at":null})
}
type ScopeRow = (String, String, bool, DateTime<Utc>, DateTime<Utc>);
fn custom((name, description, active, created, updated): ScopeRow) -> Value {
    json!({"name":name,"description":description,"source":"admin","active":active,"created_at":timestamp(created),"updated_at":timestamp(updated)})
}

async fn get(
    tx: &mut Transaction<'_, Postgres>,
    standard: &BTreeMap<String, String>,
    name: &str,
) -> Result<Response, sqlx::Error> {
    if let Some(description) = standard.get(name) {
        return Ok(Json(builtin(name, description)).into_response());
    }
    let row = sqlx::query_as::<_, ScopeRow>(
        "SELECT name,description,active,created_at,updated_at FROM oauth_scopes WHERE name=$1",
    )
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(match row {
        Some(row) => Json(custom(row)).into_response(),
        None => problem(StatusCode::NOT_FOUND, &format!("not found: {name}")),
    })
}
async fn list(
    tx: &mut Transaction<'_, Postgres>,
    standard: &BTreeMap<String, String>,
    query: &str,
) -> Result<Response, sqlx::Error> {
    let filter = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(k, _)| k == "active_only")
        .map(|(_, v)| v)
        .last();
    let active = match crate::query::active_only(filter.as_deref()) {
        Ok(active) => active,
        Err(issue) => {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":[issue]})),
            )
                .into_response());
        }
    };
    let rows = sqlx::query_as::<_, ScopeRow>(
        "SELECT name, description, active, created_at, updated_at
         FROM oauth_scopes WHERE NOT $1 OR active",
    )
    .bind(active)
    .fetch_all(&mut **tx)
    .await?;
    let mut scopes: Vec<_> = standard
        .iter()
        .map(|(name, description)| builtin(name, description))
        .chain(rows.into_iter().map(custom))
        .collect();
    scopes.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(json!({"total":scopes.len(),"scopes":scopes})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn document(response: Response) -> Value {
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn scope_inventory_includes_inactive_entries_and_reads_current_state() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE oauth_scopes (name text, description text, active boolean, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now()) ON COMMIT DROP")
            .execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO oauth_scopes (name, description, active) VALUES ('app:read', 'Read app', false)")
            .execute(&mut *tx).await.unwrap();
        let base = BTreeMap::from([("openid".into(), "Identity".into())]);
        let all = document(list(&mut tx, &base, "").await.unwrap()).await;
        assert_eq!(all["total"], 2);
        assert_eq!(all["scopes"][0]["name"], "app:read");
        assert_eq!(all["scopes"][0]["source"], "admin");
        let active = document(
            list(&mut tx, &base, "active_only=no&active_only=yes")
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(active["scopes"], json!([builtin("openid", "Identity")]));
        sqlx::query("UPDATE oauth_scopes SET active=true")
            .execute(&mut *tx)
            .await
            .unwrap();
        let entry = document(get(&mut tx, &base, "app:read").await.unwrap()).await;
        assert_eq!(entry["active"], true);
        assert!(entry["created_at"].is_string());
    }
}
