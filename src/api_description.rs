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
use std::{error::Error, io, path::PathBuf};

pub(crate) fn configured(
    production: bool,
) -> Result<(Router, Option<HeaderValue>), Box<dyn Error>> {
    let Some(path) = std::env::var_os("PYLOROS_OPENAPI_PATH") else {
        return Ok((Router::new(), None));
    };
    let path = PathBuf::from(path);
    let bytes = std::fs::read(&path)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
    let mut app = routes(bytes)?;
    if let Some(path) = std::env::var_os("PYLOROS_API_DOCS_PATH") {
        let enabled = match std::env::var("DOCS_ENABLED") {
            Err(std::env::VarError::NotPresent) => !production,
            Ok(value) => match value.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "y" | "on" | "t" => true,
                "false" | "0" | "no" | "n" | "off" | "f" => false,
                _ => return Err("Invalid DOCS_ENABLED boolean".into()),
            },
            Err(e) => return Err(e.into()),
        };
        if enabled {
            app = app.merge(browser_pages(&std::fs::read(path)?)?);
        }
    }
    let policy = std::env::var_os("PYLOROS_OPENAPI_CSP")
        .map(|p| HeaderValue::from_bytes(p.as_encoded_bytes()))
        .transpose()?;
    Ok((app, policy))
}

fn routes(bytes: Vec<u8>) -> Result<Router, Box<dyn Error>> {
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
    Ok(app)
}

#[derive(serde::Deserialize)]
struct Pages {
    swagger: String,
    redoc: String,
    oauth_redirect: String,
}

fn browser_pages(bundle: &[u8]) -> Result<Router, serde_json::Error> {
    let pages: Pages = serde_json::from_slice(bundle)?;
    let mut app = Router::new();
    for (path, page) in [
        ("/docs", pages.swagger),
        ("/redoc", pages.redoc),
        ("/docs/oauth2-redirect", pages.oauth_redirect),
    ] {
        let page = Bytes::from(page);
        app = app.route(
            path,
            get(move || {
                let page = page.clone();
                async move { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], page) }
            })
            .fallback(method_refusal),
        );
    }
    Ok(app)
}

pub(crate) fn apply_policy(app: Router, policy: Option<HeaderValue>) -> Router {
    let Some(policy) = policy else { return app };
    app.layer(axum::middleware::from_fn(
        move |request: Request, next: axum::middleware::Next| {
            let first = request.uri().path().split('/').nth(1);
            let is_docs = matches!(first, Some("docs" | "redoc" | "openapi.json"));
            let policy = policy.clone();
            async move {
                let mut response = next.run(request).await;
                if is_docs {
                    response
                        .headers_mut()
                        .entry(header::CONTENT_SECURITY_POLICY)
                        .or_insert(policy);
                }
                response
            }
        },
    ))
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
        let app = routes(source.to_vec()).unwrap();
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

    #[tokio::test]
    async fn documentation_bundle_serves_pages_and_scopes_the_browser_policy() {
        let pages = br#"{"swagger":"swagger","redoc":"redoc","oauth_redirect":"callback"}"#;
        let policy = HeaderValue::from_static("default-src 'self'");
        let app = apply_policy(
            crate::foundation::canonical_paths(browser_pages(pages).unwrap()),
            Some(policy.clone()),
        );
        for (path, status, body) in [
            ("/docs", StatusCode::OK, "swagger"),
            ("/redoc", StatusCode::OK, "redoc"),
            ("/docs/oauth2-redirect", StatusCode::OK, "callback"),
            ("/docs/?q=3", StatusCode::TEMPORARY_REDIRECT, ""),
        ] {
            let r = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(r.status(), status);
            assert_eq!(r.headers()[header::CONTENT_SECURITY_POLICY], policy);
            if status == StatusCode::TEMPORARY_REDIRECT {
                assert_eq!(r.headers()[header::LOCATION], "/docs?q=3");
            }
            assert_eq!(
                to_bytes(r.into_body(), 1024).await.unwrap().as_ref(),
                body.as_bytes()
            );
        }
        for (path, scoped) in [("/docs/missing", true), ("/redoc-other", false)] {
            let r = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                r.headers().contains_key(header::CONTENT_SECURITY_POLICY),
                scoped
            );
            assert_eq!(
                to_bytes(r.into_body(), 1024).await.unwrap().as_ref(),
                br#"{"type":"about:blank","title":"Not Found","status":404,"detail":"Not Found"}"#
            );
        }
        assert!(browser_pages(b"{}").is_err());
    }

    #[test]
    fn rejects_invalid_configured_documents() {
        for bytes in [b"{".as_slice(), b"{}", br#"{"openapi":"3.1.0","paths":{}}"#] {
            assert!(routes(bytes.to_vec()).is_err());
        }
    }
}
