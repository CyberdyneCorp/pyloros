//! Browser authorization transport for the configured issuer.
use crate::{
    browser_client::{
        self, ClientError,
        grant::{AuthorizationRequest, Decision},
    },
    browser_prompt::{self, PromptDecision, SessionAuthentication},
    login_http::problem,
    token_runtime::Runtime,
};
use axum::{
    extract::{OriginalUri, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use std::sync::Arc;

pub(crate) const PATH: &str = "/api/v1/auth/oauth2/authorize";

pub(crate) async fn method_not_allowed() -> Response {
    let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    response
        .headers_mut()
        .insert(axum::http::header::ALLOW, HeaderValue::from_static("GET"));
    response
}

fn unavailable() -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "Authorization service unavailable",
    )
}

pub(crate) fn location_header(
    target: &str,
) -> Result<HeaderValue, axum::http::header::InvalidHeaderValue> {
    use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
    // Preserve URI delimiters and existing percent escapes when serializing Location.
    const ESCAPE: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'<')
        .add(b'>')
        .add(b'\\')
        .add(b'^')
        .add(b'`')
        .add(b'{')
        .add(b'|')
        .add(b'}');
    HeaderValue::try_from(utf8_percent_encode(target, ESCAPE).to_string())
}

fn redirect(location: String) -> Response {
    match location_header(&location) {
        Ok(value) => (StatusCode::FOUND, [(LOCATION, value)]).into_response(),
        Err(_) => problem(StatusCode::BAD_REQUEST, "Invalid redirect URL"),
    }
}

fn callback(uri: &str, fields: &[(&str, &str)], state: Option<&str>) -> Response {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.extend_pairs(fields.iter().copied());
    if let Some(state) = state.filter(|s| !s.is_empty()) {
        params.append_pair("state", state);
    }
    redirect(format!("{uri}?{}", browser_prompt::encode_query(params)))
}

pub(crate) async fn authorize(
    State(rt): State<Arc<Runtime>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let fields: Vec<_> = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .into_owned()
        .collect();
    let get = |key: &str| {
        fields
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let Ok(mut tx) = rt.pool.begin().await else {
        return unavailable();
    };
    let session = match rt
        .verifier
        .browser_session(&headers, &mut tx, rt.enforce_revocation)
        .await
    {
        Ok(session) => session,
        Err(_) => return unavailable(),
    };
    let now = Utc::now();
    let prompt = browser_prompt::decide(
        get("prompt"),
        get("max_age"),
        get("auth_after"),
        session
            .as_ref()
            .map_or(SessionAuthentication::Anonymous, |s| {
                SessionAuthentication::SignedIn {
                    auth_time: s.authenticated_at.map(|t| t.timestamp()),
                }
            }),
        now,
    );
    if matches!(prompt, PromptDecision::Login { .. }) && rt.login_url.is_none() {
        return problem(
            StatusCode::UNAUTHORIZED,
            "Authentication required and no login URL is configured",
        );
    }
    let callback_uri = get("redirect_uri").unwrap_or_default();
    let client = match browser_client::resolve(&mut tx, get("client_id"), Some(callback_uri)).await
    {
        Ok(client) => client,
        Err(ClientError::Database(_)) => return unavailable(),
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let state = get("state");
    let error = |code: &str, description: &str| {
        callback(
            callback_uri,
            &[("error", code), ("error_description", description)],
            state,
        )
    };
    match prompt {
        PromptDecision::Error { code, description } => return error(code, &description),
        PromptDecision::Login { fresh } => {
            let Ok(issuer) = url::Url::parse(rt.signer.issuer()) else {
                return unavailable();
            };
            let target = format!(
                "{}{}",
                issuer.origin().ascii_serialization(),
                uri.path_and_query().map_or(PATH, |p| p.as_str())
            );
            return redirect(browser_prompt::login_location(
                rt.login_url.as_deref().unwrap_or_default(),
                &target,
                fresh,
                now,
            ));
        }
        PromptDecision::Proceed => {}
    }
    let Some(session) = session else {
        return unavailable();
    };
    let resources: Vec<_> = fields
        .iter()
        .filter(|(k, _)| k == "resource")
        .map(|(_, v)| v.clone())
        .collect();
    let request = AuthorizationRequest {
        response_type: get("response_type"),
        scope: get("scope"),
        challenge: get("code_challenge"),
        challenge_method: get("code_challenge_method"),
        resources: &resources,
        nonce: get("nonce").map(str::to_owned),
        silent: get("prompt").is_some_and(|p| p.split_whitespace().any(|s| s == "none")),
    };
    let registry = rt.resources.borrow().clone();
    let Some(expiration) = now.checked_add_signed(rt.code_ttl) else {
        return unavailable();
    };
    let user = session.user;
    match client
        .authorize(&mut tx, session, request, &registry.scopes, expiration)
        .await
    {
        Ok(Decision::Issued(code)) => match tx.commit().await {
            Ok(()) => callback(callback_uri, &[("code", &code)], state),
            Err(_) => unavailable(),
        },
        Ok(Decision::Denied {
            error: code,
            description,
        }) => error(code, &description),
        Ok(Decision::Approval { resource, scopes }) => {
            let Some(page) = &rt.consent_page else {
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Interactive consent unavailable",
                );
            };
            let details = crate::consent_page::Approval {
                client: &client,
                user,
                resource: &resource,
                scopes: &scopes,
                query: uri.query().unwrap_or_default(),
            };
            match page.render(&mut tx, &rt.signer, details, now).await {
                Ok(response) => response,
                Err(_) => unavailable(),
            }
        }
        Err(_) => unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[test]
    fn redirect_header_encodes_unicode_and_preserves_existing_uri_escapes() {
        let target = "https://client.example/Καλημέρα hello/%2F?q=a+b&state=%C3%A9#section";
        assert_eq!(
            location_header(target).unwrap(),
            "https://client.example/%CE%9A%CE%B1%CE%BB%CE%B7%CE%BC%CE%AD%CF%81%CE%B1%20hello/%2F?q=a+b&state=%C3%A9#section"
        );
        assert_eq!(location_header("/a\r\nb").unwrap(), "/a%0D%0Ab");
    }

    #[tokio::test]
    async fn disabled_provider_reports_local_errors_and_only_accepts_get() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/unused")
            .unwrap();
        let routes = crate::token_http::routes(None, pool, false).await.unwrap();
        for (method, status) in [
            ("GET", StatusCode::NOT_FOUND),
            ("HEAD", StatusCode::METHOD_NOT_ALLOWED),
            ("POST", StatusCode::METHOD_NOT_ALLOWED),
        ] {
            let response = routes
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(PATH)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert!(!response.headers().contains_key(LOCATION));
            if status == StatusCode::METHOD_NOT_ALLOWED {
                assert_eq!(response.headers()["allow"], "GET");
            }
        }
    }
}
