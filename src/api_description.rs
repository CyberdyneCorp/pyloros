//! Serve the OpenAPI description selected by the deployment.
use axum::{
    Router,
    body::Bytes,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{any, get},
};
use serde_json::Value;
use std::{error::Error, ffi::OsString, io, path::PathBuf};

pub(crate) fn configured() -> Result<Router, Box<dyn Error>> {
    let Some(path) = std::env::var_os("PYLOROS_OPENAPI_PATH") else {
        return Ok(Router::new());
    };
    let path = PathBuf::from(path);
    let bytes = std::fs::read(&path)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
    routes(bytes, std::env::var_os("PYLOROS_OPENAPI_CSP"))
}

fn routes(bytes: Vec<u8>, policy: Option<OsString>) -> Result<Router, Box<dyn Error>> {
    let document: Value = serde_json::from_slice(&bytes)?;
    if !document["openapi"]
        .as_str()
        .is_some_and(|v| v.starts_with("3."))
        || !document["info"]["title"].is_string()
        || !document["info"]["version"].is_string()
        || !document["paths"].is_object()
    {
        return Err("Expected an OpenAPI 3 HTTP document with info and paths".into());
    }
    let bytes = Bytes::from(bytes);
    let app = Router::new()
        .route(
            "/openapi.json",
            get(move || {
                let body = bytes.clone();
                async move { ([(header::CONTENT_TYPE, "application/json")], body) }
            })
            .fallback(method_refusal),
        )
        .route("/openapi.json/", any(redirect));
    let Some(policy) = policy else { return Ok(app) };
    let policy = HeaderValue::from_str(policy.to_str().ok_or("Invalid schema policy")?)?;
    Ok(app.layer(axum::middleware::map_response(
        move |mut response: Response| {
            response
                .headers_mut()
                .insert(header::CONTENT_SECURITY_POLICY, policy.clone());
            async move { response }
        },
    )))
}

async fn redirect(origin: crate::foundation::RequestOrigin, request: Request) -> Redirect {
    let mut location = origin.0.unwrap_or_default();
    location.push_str("/openapi.json");
    if let Some(query) = request.uri().query() {
        location.push('?');
        location.push_str(query);
    }
    Redirect::temporary(&location)
}

async fn method_refusal() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "GET, HEAD"), (header::CONTENT_TYPE, "application/json")],
        r#"{"type":"about:blank","title":"Method Not Allowed","status":405,"detail":"Method Not Allowed"}"#,
    ).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Method,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn serves_the_document_and_its_length_on_the_standard_methods() {
        let source =
            br#"{"openapi":"3.1.0", "info":{"title":"Example","version":"1"}, "paths":{}}"#;
        let app = routes(source.to_vec(), None).unwrap();
        for method in [Method::GET, Method::HEAD] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/openapi.json")
                        .method(method.clone())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(
                response.headers()[header::CONTENT_LENGTH],
                source.len().to_string()
            );
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                &body[..],
                if method == Method::GET {
                    &source[..]
                } else {
                    &[]
                }
            );
        }
    }

    #[tokio::test]
    async fn unsupported_methods_return_the_wire_problem_document() {
        let response = method_refusal().await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "GET, HEAD");
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(body.as_ref(), br#"{"type":"about:blank","title":"Method Not Allowed","status":405,"detail":"Method Not Allowed"}"#);
    }

    #[test]
    fn rejects_invalid_configured_documents() {
        for bytes in [b"{".as_slice(), b"{}", br#"{"openapi":"3.1.0","paths":{}}"#] {
            assert!(routes(bytes.to_vec(), None).is_err());
        }
    }
}
