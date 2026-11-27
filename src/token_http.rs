//! HTTP transport for the authorization-code grant.
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
    let configured = ResourceRegistry::from_env()?;
    let Some(provider) = provider else {
        return Ok(Router::new()
            .merge(crate::consent_http::routes(None))
            .route(
                browser_http::PATH,
                get(|| async {
                    crate::login_http::problem(StatusCode::NOT_FOUND, "OIDC disabled")
                })
                .head(method_not_allowed)
                .fallback(method_not_allowed),
            ));
    };
    let Some(runtime) = Runtime::load(provider, pool, production, configured).await? else {
        return Ok(Router::new());
    };
    let runtime = Arc::new(runtime);
    Ok(Router::new()
        .route("/api/v1/auth/oauth2/token", post(exchange))
        .route(
            browser_http::PATH,
            get(browser_http::authorize)
                .head(method_not_allowed)
                .fallback(method_not_allowed),
        )
        .with_state(runtime.clone())
        .merge(crate::consent_http::routes(Some(runtime))))
}

pub(crate) fn header<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key)?.to_str().ok()
}

fn basic(headers: &HeaderMap) -> Option<(String, String)> {
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
    State(rt): State<Arc<Runtime>>,
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
    if grant != "authorization_code" {
        return (StatusCode::BAD_REQUEST,Json(json!({"error":"unsupported_grant_type","error_description":format!("grant_type {grant:?} is not supported")}))).into_response();
    }
    let (id, secret) = basic(&headers).unwrap_or_default();
    let resources = fields
        .iter()
        .filter(|(k, _)| k == "resource")
        .map(|(_, v)| v.clone())
        .collect::<Vec<_>>();
    let req = ExchangeRequest {
        client_id: if id.is_empty() {
            get("client_id").unwrap_or_default()
        } else {
            &id
        },
        client_secret: if secret.is_empty() {
            get("client_secret")
        } else {
            Some(&secret)
        },
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
    let origin = SessionOrigin {
        user_agent: header(&headers, "user-agent"),
        ip: client_ip(&headers, peer.ip(), rt.trusted_proxies),
    };
    match rt
        .signer
        .exchange_code(
            &rt.pool,
            &req,
            &settings,
            origin,
            header(&headers, "x-request-id"),
            chrono::Utc::now(),
        )
        .await
    {
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
        Err(_) => {
            eprintln!("authorization code exchange failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
            )
                .into_response()
        }
    }
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
