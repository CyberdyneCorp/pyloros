use super::*;
use crate::{browser_http::location_header, browser_prompt::encode_query, csrf::cookie};
use axum::{
    http::{HeaderValue, Method},
    response::Html,
};

fn method_refused() -> Response {
    let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    response
        .headers_mut()
        .insert(h::ALLOW, HeaderValue::from_static("GET"));
    response
}

pub(super) async fn disabled(method: Method) -> Response {
    if method == Method::GET || method == Method::POST {
        problem(StatusCode::NOT_FOUND, "OIDC disabled")
    } else {
        method_refused()
    }
}

pub(super) async fn handle(
    State(state): State<Option<Arc<Login>>>,
    base: crate::foundation::RequestOrigin,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let headers = req.headers().clone();
    let form = req.method() == Method::POST;
    let params = match *req.method() {
        Method::GET => {
            url::form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
                .into_owned()
                .collect()
        }
        Method::POST => match crate::token_http::fields(req).await {
            Ok(fields) => fields,
            Err(response) => return *response,
        },
        _ => return method_refused(),
    };
    let Some(login) = state else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Logout unavailable");
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), login.proxies),
        user_agent: header(&headers, "user-agent"),
    };
    let Ok(cleared) = login
        .logout(
            logout::LogoutKind::Oidc,
            cookie(&headers, "access_token"),
            cookie(&headers, "refresh_token"),
            origin,
            header(&headers, "x-request-id"),
        )
        .await
    else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Logout unavailable");
    };
    let mut response = destination(
        &login,
        params,
        form,
        login.oidc_issuer.as_deref().or(base.0.as_deref()),
    )
    .await;
    for value in cleared.headers().get_all(h::SET_COOKIE) {
        response.headers_mut().append(h::SET_COOKIE, value.clone());
    }
    response
}

fn refused(detail: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"detail":detail}))).into_response()
}

async fn destination(
    login: &Login,
    params: Vec<(String, String)>,
    form: bool,
    issuer: Option<&str>,
) -> Response {
    let get = |key: &str| {
        params
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .filter(|v| !form || !v.is_empty())
    };
    let hint = get("id_token_hint").and_then(|raw| login.verifier.logout_client_hint(raw, issuer));
    let client = get("client_id");
    if let (Some(hint), Some(id)) = (hint.as_deref(), client)
        && hint != id
    {
        return refused("client_id does not match the id_token_hint audience");
    }
    let Some(target) = get("post_logout_redirect_uri") else {
        return Html(login.signed_out.clone()).into_response();
    };
    let Some(id) = client.filter(|s| !s.is_empty()).or(hint.as_deref()) else {
        return refused("post_logout_redirect_uri requires a valid id_token_hint or client_id");
    };
    let registered = sqlx::query_scalar::<_, bool>(
        "SELECT coalesce(post_logout_redirect_uris::jsonb ? $2, false) FROM oauth_clients WHERE active AND client_id=$1",
    )
    .bind(id)
    .bind(target)
    .fetch_optional(&login.pool)
    .await;
    match registered {
        Ok(Some(true)) => {}
        Ok(Some(false)) => {
            return refused("post_logout_redirect_uri is not registered for this client");
        }
        Ok(None) => return refused("unknown client"),
        Err(_) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Client registry unavailable",
            );
        }
    }
    let mut location = target.to_owned();
    if let Some(state) = get("state") {
        location.push(if target.contains('?') { '&' } else { '?' });
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("state", state);
        location.push_str(&encode_query(query));
    }
    match location_header(&location) {
        Ok(value) => (StatusCode::FOUND, [(h::LOCATION, value)]).into_response(),
        Err(_) => refused("Invalid redirect URL"),
    }
}
