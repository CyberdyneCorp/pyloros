//! OAuth token endpoint for service and authorization-code grants.
mod dcr;
pub(crate) use dcr::configured_origins as configured_registration_origins;
mod device;
mod device_browser;
mod device_poll;
mod refresh;
mod service;
use crate::{
    browser_http::{self, method_not_allowed},
    code_decision::CodeDecision,
    code_exchange::ExchangeRequest,
    discovery::Provider,
    grant_response::{GrantSettings, SessionOrigin},
    token_runtime::{ResourceRegistry, Runtime},
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, FromRequest, Multipart, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use sqlx::PgPool;
use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

pub async fn routes(
    provider: Option<&Provider>,
    pool: PgPool,
    production: bool,
) -> Result<Router, Box<dyn Error>> {
    let configured = configured_resources(provider)?;
    let resources = if provider.is_some() {
        crate::token_runtime::resource_registry(
            pool.clone(),
            configured,
            crate::token_runtime::number("OAUTH_REGISTRY_REFRESH_SECONDS", 30)?.try_into()?,
        )
        .await
    } else {
        tokio::sync::watch::channel(Arc::new(configured)).1
    };
    routes_with_resources(provider, pool, production, resources).await
}

pub(crate) async fn routes_with_resources(
    provider: Option<&Provider>,
    pool: PgPool,
    production: bool,
    resources: crate::token_runtime::ResourceCatalog,
) -> Result<Router, Box<dyn Error>> {
    let register = provider.is_some_and(Provider::dynamic_registration_enabled);
    let code = match provider {
        Some(provider) => Runtime::load(provider, pool.clone(), production, resources.clone())
            .await?
            .map(Arc::new),
        None => None,
    };
    let proxies = crate::token_runtime::number("TRUSTED_PROXY_COUNT", 0)?.try_into()?;
    let device = device::routes(provider, pool.clone(), proxies)?;
    let browser = device_browser::routes(provider, code.clone(), proxies)?;
    let registration = dcr::routes(register, resources, pool.clone(), proxies)?;
    let state = Endpoint {
        service: service::Issuer::configured(pool, production)?,
        code: code.clone(),
        oidc: provider.is_some(),
        device: provider.is_some_and(Provider::device_authorization_enabled),
        proxies,
    };
    let token = Router::new()
        .route("/api/v1/auth/oauth2/token", post(exchange))
        .with_state(Arc::new(state))
        .merge(device)
        .merge(browser)
        .merge(registration);
    if let Some(runtime) = code {
        return Ok(token
            .merge(
                Router::new()
                    .route(
                        browser_http::PATH,
                        get(browser_http::authorize)
                            .head(method_not_allowed)
                            .fallback(method_not_allowed),
                    )
                    .with_state(runtime.clone()),
            )
            .merge(crate::consent_http::routes(Some(runtime))));
    }
    if provider.is_some() {
        return Ok(token);
    }
    Ok(token.merge(crate::consent_http::routes(None)).route(
        browser_http::PATH,
        get(|| async { crate::login_http::problem(StatusCode::NOT_FOUND, "OIDC disabled") })
            .head(method_not_allowed)
            .fallback(method_not_allowed),
    ))
}

pub(crate) fn configured_resources(
    provider: Option<&Provider>,
) -> Result<ResourceRegistry, Box<dyn Error>> {
    let mut configured = ResourceRegistry::from_env()?;
    if provider.is_some_and(Provider::dynamic_registration_enabled) {
        configured.registration_origins = Some(dcr::configured_origins()?);
    }
    Ok(configured)
}

struct Endpoint {
    service: Option<service::Issuer>,
    code: Option<Arc<Runtime>>,
    oidc: bool,
    device: bool,
    proxies: usize,
}

pub(crate) fn header<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key)?.to_str().ok()
}

pub(crate) fn basic(headers: &HeaderMap) -> Option<(String, String)> {
    let (scheme, value) = header(headers, "authorization")?.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(value.trim()).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.into(), secret.into()))
}

pub(crate) fn client_ip(headers: &HeaderMap, peer: IpAddr, proxies: usize) -> Option<IpAddr> {
    if proxies > 0
        && let Some(xff) = header(headers, "x-forwarded-for")
    {
        let hops = xff
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if let Some(ip) = hops.get(hops.len().saturating_sub(proxies)) {
            return ip.parse().ok();
        }
    }
    Some(peer)
}

type Fields = Vec<(String, String)>;
pub(crate) async fn fields(req: Request) -> Result<Fields, Box<Response>> {
    let mime = header(req.headers(), "content-type")
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if mime.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        let bytes = axum::body::Bytes::from_request(req, &())
            .await
            .map_err(IntoResponse::into_response)?;
        return Ok(url::form_urlencoded::parse(&bytes).into_owned().collect());
    }
    let mut values = Vec::new();
    if mime.eq_ignore_ascii_case("multipart/form-data") {
        let mut form = Multipart::from_request(req, &())
            .await
            .map_err(IntoResponse::into_response)?;
        while let Some(field) = form
            .next_field()
            .await
            .map_err(IntoResponse::into_response)?
        {
            if let Some(name) = field.name().map(str::to_owned) {
                values.push((
                    name,
                    field.text().await.map_err(IntoResponse::into_response)?,
                ));
            }
        }
    }
    Ok(values)
}

async fn exchange(
    State(endpoint): State<Arc<Endpoint>>,
    origin_base: crate::foundation::RequestOrigin,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let headers = req.headers().clone();
    let fields = match fields(req).await {
        Ok(fields) => fields,
        Err(response) => return *response,
    };
    let get = |name: &str| {
        fields
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    };
    let Some(grant) = get("grant_type") else {
        return (StatusCode::UNPROCESSABLE_ENTITY,Json(json!({"detail":[{"type":"missing","loc":["body","grant_type"],"msg":"Field required","input":null}]}))).into_response();
    };
    let (id, secret) = basic(&headers).unwrap_or_default();
    let client = if id.is_empty() {
        get("client_id").unwrap_or_default()
    } else {
        &id
    };
    let secret = if secret.is_empty() {
        get("client_secret")
    } else {
        Some(secret.as_str())
    };
    let origin = SessionOrigin {
        user_agent: header(&headers, "user-agent"),
        ip: client_ip(&headers, peer.ip(), endpoint.proxies),
    };
    let polling = endpoint.device && grant == device::GRANT;
    if !polling && !matches!(grant, "authorization_code" | "refresh_token") {
        let request = service::Request {
            grant,
            client,
            secret,
            scope: get("scope"),
            audience: get("audience"),
            origin,
        };
        return exchange_service(&endpoint, request).await;
    }
    if !endpoint.oidc {
        return (StatusCode::BAD_REQUEST,Json(json!({"error":"unsupported_grant_type","error_description":format!("grant_type '{grant}' is not enabled")}))).into_response();
    }
    let Some(rt) = &endpoint.code else {
        return crate::login_http::problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Token signing unavailable",
        );
    };
    let resources = fields
        .iter()
        .filter(|(k, _)| k == "resource")
        .map(|(_, v)| v.clone())
        .collect::<Vec<_>>();
    let req = ExchangeRequest {
        client_id: client,
        client_secret: secret,
        code: get("code").unwrap_or_default(),
        verifier: get("code_verifier").unwrap_or_default(),
        redirect_uri: get("redirect_uri"),
        resources: &resources,
    };
    let registry = rt.resources.borrow().clone();
    let settings = GrantSettings {
        access_lifetime: rt.access_ttl,
        id_lifetime: rt.id_ttl,
        admin_emails: &rt.admins,
        require_verified_admin_email: rt.production,
        resources: &registry.audiences,
    };
    let request_id = header(&headers, "x-request-id");
    let now = chrono::Utc::now();
    let Some(id_issuer) = rt.oidc_issuer.as_deref().or(origin_base.0.as_deref()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let signer = rt.signer.for_id_issuer(id_issuer);
    let decision = if polling {
        device_poll::exchange(
            rt,
            &signer,
            device_poll::Request {
                client,
                secret,
                code: get("device_code"),
                resource: !resources.is_empty(),
            },
            &settings,
            origin,
            request_id,
            now,
        )
        .await
    } else if grant == "refresh_token" {
        refresh::exchange(
            rt,
            &signer,
            refresh::Request {
                client,
                secret,
                token: get("refresh_token"),
                scope: get("scope"),
                resources: &resources,
                registry: &registry.scopes,
            },
            &settings,
            origin,
            request_id,
            now,
        )
        .await
    } else {
        signer
            .exchange_code(&rt.pool, &req, &settings, origin, request_id, now)
            .await
    };
    exchange_response(decision)
}

async fn exchange_service(endpoint: &Endpoint, request: service::Request<'_>) -> Response {
    let Some(issuer) = &endpoint.service else {
        return crate::login_http::problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Token signing unavailable",
        );
    };
    issuer
        .exchange(request)
        .await
        .unwrap_or_else(|_| internal())
}

fn exchange_response(
    decision: Result<CodeDecision, crate::grant_sessions::SessionError>,
) -> Response {
    match decision {
        Ok(CodeDecision::Issued(body)) => (
            [("cache-control", "no-store"), ("pragma", "no-cache")],
            Json(body),
        )
            .into_response(),
        Ok(CodeDecision::Refused(error)) => (
            StatusCode::from_u16(error.status()).expect("OAuth status"),
            Json(error),
        )
            .into_response(),
        Err(err @ crate::grant_sessions::SessionError::UnsupportedIdToken) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"server_error", "error_description":err.to_string()})),
        )
            .into_response(),
        Err(_) => {
            eprintln!("OAuth token exchange failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
            )
                .into_response()
        }
    }
}

pub(crate) async fn post_only() -> Response {
    let mut response =
        crate::login_http::problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    response.headers_mut().insert(
        axum::http::header::ALLOW,
        axum::http::HeaderValue::from_static("POST"),
    );
    response
}

fn internal() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[tokio::test]
    async fn repeated_resources_survive_form_decoding() {
        let req = Request::post("/api/v1/auth/oauth2/token")
            .header(
                "content-type",
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .body(Body::from(
                "resource=https%3A%2F%2Fa.test&resource=https%3A%2F%2Fb.test",
            ))
            .unwrap();
        assert_eq!(
            fields(req).await.unwrap(),
            [
                ("resource".into(), "https://a.test".into()),
                ("resource".into(), "https://b.test".into())
            ]
        );
    }

    #[test]
    fn credentials_and_proxy_hops_follow_configured_boundaries() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "bASic YXBwOnNlY3JldDp0YWls".parse().unwrap(),
        );
        assert_eq!(basic(&headers), Some(("app".into(), "secret:tail".into())));
        headers.insert("authorization", "Basic %%%".parse().unwrap());
        assert!(basic(&headers).is_none());
        headers.insert("x-forwarded-for", "192.0.2.10, 192.0.2.11".parse().unwrap());
        let peer = "127.0.0.1".parse().unwrap();
        assert_eq!(client_ip(&headers, peer, 0), Some(peer));
        assert_eq!(client_ip(&headers, peer, 1), "192.0.2.11".parse().ok());
        assert_eq!(client_ip(&headers, peer, 2), "192.0.2.10".parse().ok());
    }
}
