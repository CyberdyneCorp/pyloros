//! Public OAuth client registration and its administrative audit record.
mod input;
use super::{client_ip, header, internal, post_only};
use crate::client_auth::opaque;
use crate::{
    browser_client,
    browser_prompt::quoted_string,
    grant_response::SessionOrigin,
    login_http::problem,
    login_throttle::LoginThrottle,
    passwords::PasswordScheme,
    token_runtime::{ResourceCatalog, ResourceRegistry, number},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use chrono::Utc;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{collections::BTreeSet, env, error::Error, net::SocketAddr, sync::Arc, time::Duration};
use uuid::Uuid;

const PATH: &str = "/api/v1/auth/oauth2/register";
struct Registration {
    pool: PgPool,
    resources: ResourceCatalog,
    quota: LoginThrottle,
    proxies: usize,
}
pub(super) fn routes(
    enabled: bool,
    resources: ResourceCatalog,
    pool: PgPool,
    proxies: usize,
) -> Result<Router, Box<dyn Error>> {
    let state = if enabled {
        Some(Arc::new(Registration {
            pool,
            resources,
            quota: LoginThrottle::with_window(
                number("RATELIMIT_DCR_PER_HOUR", 10)?,
                Duration::from_secs(3600),
            ),
            proxies,
        }))
    } else {
        None
    };
    Ok(Router::new()
        .route(PATH, post(register).fallback(post_only))
        .with_state(state))
}

pub(super) fn configured_origins() -> Result<BTreeSet<String>, Box<dyn Error>> {
    let raw = env::var("OAUTH_DCR_ALLOWED_REDIRECT_ORIGINS").unwrap_or_default();
    let entries: Vec<String> = if raw.trim_start().starts_with('[') {
        serde_json::from_str(&raw)?
    } else {
        raw.split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect()
    };
    let mut origins = BTreeSet::new();
    for value in entries {
        let bare = value.trim_end_matches('/').to_ascii_lowercase();
        if https_origin(&value).as_deref() != Some(bare.as_str()) {
            return Err("invalid dynamic registration redirect origin".into());
        }
        origins.insert(bare);
    }
    Ok(origins)
}

fn https_origin(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https")
        || uri.contains(['#', '\\'])
        || uri.bytes().any(|c| c.is_ascii_control() || c == b' ')
    {
        return None;
    }
    let raw = rest.split(['/', '?']).next()?;
    if raw.contains('@') {
        return None;
    }
    let authority: axum::http::uri::Authority = raw.parse().ok()?;
    if authority.host().is_empty()
        || (!raw[authority.host().len()..].is_empty() && authority.port_u16().is_none())
    {
        return None;
    }
    Some(format!("https://{}", raw.to_ascii_lowercase()))
}

struct Client {
    name: String,
    uris: BTreeSet<String>,
    grants: BTreeSet<String>,
    scope: String,
}
fn metadata(input: input::Metadata, registry: &ResourceRegistry) -> Result<Client, Value> {
    let invalid = |msg: &str| json!({"error":"invalid_client_metadata","error_description":msg});
    if input.method.as_deref().is_some_and(|m| m != "none") {
        return Err(invalid(
            "only public clients may self-register (token_endpoint_auth_method=none)",
        ));
    }
    if input.responses.iter().any(|v| v != "code") {
        return Err(invalid("response_types must be [\"code\"]"));
    }
    let grants: BTreeSet<_> = if input.grants.is_empty() {
        ["authorization_code".into(), "refresh_token".into()].into()
    } else {
        input.grants.into_iter().collect()
    };
    if grants.contains(super::device::GRANT) {
        return Err(invalid(
            "the device_code grant is not available to dynamically registered clients",
        ));
    }
    if !grants.contains("authorization_code")
        || grants
            .iter()
            .any(|g| !matches!(g.as_str(), "authorization_code" | "refresh_token"))
    {
        return Err(invalid(
            "grant_types must be authorization_code (optionally with refresh_token)",
        ));
    }
    if input.redirects.is_empty() {
        return Err(
            json!({"error":"invalid_redirect_uri","error_description":"between 1 and 10 redirect_uris required"}),
        );
    }
    for uri in &input.redirects {
        if browser_client::loopback(uri).is_none()
            && !https_origin(uri).is_some_and(|o| {
                registry
                    .registration_origins
                    .as_ref()
                    .is_some_and(|origins| origins.contains(&o))
            })
        {
            return Err(
                json!({"error":"invalid_redirect_uri","error_description":format!("redirect_uri must be loopback http or an allowlisted https origin: {}",quoted_string(uri))}),
            );
        }
    }
    let mut allowed = registry.registration_scopes();
    let requested: BTreeSet<_> = input
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    if !requested.is_empty() {
        allowed.retain(|s| requested.contains(s));
    }
    let name: String = input
        .name
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(128)
        .collect();
    Ok(Client {
        name: if name.is_empty() {
            "Unnamed MCP client".into()
        } else {
            name
        },
        uris: input.redirects.into_iter().collect(),
        grants,
        scope: allowed.into_iter().collect::<Vec<_>>().join(" "),
    })
}

async fn register(
    State(state): State<Option<Arc<Registration>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    if !bytes.is_empty() {
        if !crate::request_json::is_json(&headers) {
            return internal();
        }
        if std::str::from_utf8(&bytes).is_err() {
            return problem(
                StatusCode::BAD_REQUEST,
                "There was an error parsing the body",
            );
        }
    }
    let body = crate::request_json::parse_body(&headers, &bytes)
        .map_err(|e| vec![e])
        .and_then(input::parse);
    let data = match body {
        Ok(d) => d,
        Err(issues) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":issues})),
            )
                .into_response();
        }
    };
    let Some(state) = state else {
        return problem(StatusCode::NOT_FOUND, "Not found");
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: header(&headers, "user-agent"),
    };
    if !state.quota.allow(origin.ip) {
        let mut response = problem(StatusCode::TOO_MANY_REQUESTS, "Too many requests");
        response
            .headers_mut()
            .insert("retry-after", "3600".parse().unwrap());
        return response;
    }
    let client = match metadata(data, &state.resources.borrow()) {
        Ok(c) => c,
        Err(body) => return (StatusCode::BAD_REQUEST, Json(body)).into_response(),
    };
    match persist(&state.pool, client, origin).await {
        Ok(body) => (
            StatusCode::CREATED,
            [("cache-control", "no-store")],
            Json(body),
        )
            .into_response(),
        Err(_) => internal(),
    }
}

async fn persist(
    pool: &PgPool,
    client: Client,
    origin: SessionOrigin<'_>,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let id = format!("dcr_{}", opaque::<12>());
    let hash = PasswordScheme::Argon2.hash(opaque::<32>()).await?;
    let grants = client
        .grants
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, secret_hash, name, redirect_uris, allowed_scopes,
             grant_types, client_type, registration_source, trusted)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'public','dynamic',false)",
    )
    .bind(Uuid::new_v4())
    .bind(&id)
    .bind(hash)
    .bind(&client.name)
    .bind(json!(client.uris))
    .bind(&client.scope)
    .bind(grants)
    .execute(&mut *tx)
    .await?;
    crate::admin_audit::append_client_action(
        &mut tx,
        "oauth_client.dynamic_register",
        None,
        &id,
        json!({"name":client.name,"redirect_uris":client.uris}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(
        json!({"client_id":id,"client_id_issued_at":Utc::now().timestamp(),"client_name":client.name,"redirect_uris":client.uris,
        "grant_types":client.grants,"response_types":["code"],"token_endpoint_auth_method":"none","scope":client.scope}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_active_resource_cannot_grant_a_dynamic_client_privileged_scopes() {
        let mut registry = ResourceRegistry::default();
        registry.scopes.insert(
            "https://resource.example".into(),
            [
                "files.read",
                "roles:manage",
                "users:provision",
                "directory:read",
                "iam:read.tier",
                "admin:new",
            ]
            .map(String::from)
            .into(),
        );
        let payload = json!({"redirect_uris":["http://[::1]:4333/cb"],"scope":"files.read openid roles:manage users:provision directory:read iam:read.tier admin:new"});
        let client = metadata(input::parse(payload).unwrap(), &registry).unwrap();
        assert_eq!(client.scope, "files.read openid");
    }
}
