use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
};
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use tower::ServiceExt;

#[tokio::test]
async fn administrative_oauth_routes_advertise_methods_only_on_method_errors() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    for (path, allowed) in [
        ("clients", "POST"),
        ("clients/test", "GET"),
        ("scopes", "GET"),
        ("scopes/openid", "GET"),
        ("protected-resources", "GET"),
        ("protected-resources/test", "GET"),
        ("web-origins", "GET"),
        ("web-origins/test", "GET"),
    ] {
        for (method, expected_status, allow) in [
            (Method::GET, StatusCode::UNAUTHORIZED, None),
            (Method::TRACE, StatusCode::METHOD_NOT_ALLOWED, Some(allowed)),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(format!("/api/v1/admin/oauth/{path}"))
                .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
                .body(Body::empty())
                .unwrap();
            let response = routes.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected_status, "{path}");
            assert_eq!(
                response
                    .headers()
                    .get(header::ALLOW)
                    .map(|v| v.to_str().unwrap()),
                allow,
                "{path}"
            );
        }
    }
}

#[tokio::test]
async fn operator_delete_routes_authenticate_before_validating_the_target() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    for target in [
        "users/bulk",
        "users/invalid",
        "users/invalid/roles/app/reader?organization_id=invalid",
        "organizations/invalid",
    ] {
        let request = Request::delete(format!("/api/v1/admin/{target}"))
            .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            routes.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn role_session_routes_preserve_method_priority_at_their_intersection() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    for (method, path, status, allowed) in [
        (Method::GET, "sessions/policies", 405, Some("POST")),
        (Method::POST, "sessions/policies", 401, None),
        (Method::DELETE, "sessions/policies", 401, None),
        (Method::GET, "unknown/policies/unknown", 405, Some("DELETE")),
        (Method::GET, "sessions/sessions", 401, None),
        (Method::DELETE, "sessions/sessions", 401, None),
        (Method::POST, "sessions/sessions", 401, None),
        (Method::POST, "sessions/unknown", 405, Some("DELETE")),
        (Method::HEAD, "sessions/sessions", 405, Some("GET")),
        (Method::PUT, "sessions/sessions", 405, Some("GET")),
        (Method::GET, "sessions/unknown", 405, Some("DELETE")),
        (Method::DELETE, "unknown/sessions", 405, Some("GET")),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(format!("/api/v1/admin/roles/{path}"))
            .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
            .body(Body::empty())
            .unwrap();
        let response = routes.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(
            response
                .headers()
                .get(header::ALLOW)
                .map(|v| v.to_str().unwrap()),
            allowed
        );
    }
}

#[tokio::test]
async fn role_policy_attachment_authenticates_after_decoding_nonfinite_numbers() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    let request = Request::post("/api/v1/admin/roles/invalid/policies")
        .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"policy_id":NaN}"#))
        .unwrap();
    assert_eq!(
        routes.oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn delegated_reads_require_service_bearer_credentials() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    for path in [
        "permissions?client_id=another",
        "roles?client_id=another",
        "roles/reader/permissions",
        "users/invalid/roles",
    ] {
        for (name, value) in [
            (header::COOKIE, "access_token=user-session"),
            (header::AUTHORIZATION, "Basic test"),
            (header::AUTHORIZATION, "Bearer invalid"),
        ] {
            let request = Request::get(format!("/api/v1/clients/me/{path}"))
                .header(name, value)
                .body(Body::empty())
                .unwrap();
            let response = routes.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
            let body = axum::body::to_bytes(response.into_body(), 256)
                .await
                .unwrap();
            let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["detail"], "Service token required");
        }
    }
}

#[tokio::test]
async fn delegated_catalog_writes_require_service_credentials() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    for (method, path) in [
        (Method::POST, "/api/v1/clients/me/permissions"),
        (Method::DELETE, "/api/v1/clients/me/permissions/read"),
        (Method::POST, "/api/v1/clients/me/roles"),
        (Method::PUT, "/api/v1/clients/me/roles/reader/permissions"),
        (Method::POST, "/api/v1/clients/me/users/invalid/roles"),
        (
            Method::DELETE,
            "/api/v1/clients/me/users/invalid/roles/reader",
        ),
        (Method::DELETE, "/api/v1/clients/me/roles/reader"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
            .header(header::COOKIE, "access_token=user-session")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"client_id":"other","key":"read"}"#))
            .unwrap();
        let response = routes.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
        let bytes = axum::body::to_bytes(response.into_body(), 256)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["detail"], "Service token required");
    }
}

#[tokio::test]
async fn hook_authoring_authenticates_large_json_envelopes() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    let mut json = Vec::from(b"{}");
    json.resize((2 << 20) + 1, b' ');
    for (method, path) in [
        (Method::POST, "hooks"),
        (Method::PUT, "hooks/invalid"),
        (Method::PUT, "hooks/validate"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(format!("/api/v1/admin/{path}"))
            .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json.clone()))
            .unwrap();
        let response = routes.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn authenticator_changes_challenge_anonymous_well_formed_utf16_requests() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    let body = [0xff, 0xfe]
        .into_iter()
        .chain(r#"{"password":[],"code":1}"#.encode_utf16().flat_map(u16::to_le_bytes))
        .collect::<Vec<_>>();
    for operation in ["enable", "disable", "recovery-codes"] {
        let request = Request::post(format!("/api/v1/auth/mfa/totp/{operation}"))
            .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.clone()))
            .unwrap();
        let response = routes.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{operation}");
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
    }
}

#[tokio::test]
async fn account_creation_authenticates_before_validating_large_numeric_fields() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let router = pyloros::profile::routes(pool, false).unwrap();
    let digits = "7".repeat(402);
    let document = format!(
        r#"{{"email":{digits},"extra":"{}"}}"#,
        "x".repeat(2 * 1024 * 1024)
    );
    let request = Request::post("/api/v1/admin/users")
        .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(document))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn padded_catalog_writes_reach_authorization() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    for (method, path) in [
        (Method::POST, "/api/v1/admin/clients/example/roles"),
        (Method::POST, "/api/v1/clients/me/roles"),
        (Method::POST, "/api/v1/admin/clients/example/permissions"),
        (Method::POST, "/api/v1/clients/me/permissions"),
        (
            Method::PUT,
            "/api/v1/admin/clients/example/roles/reader/permissions",
        ),
        (Method::PUT, "/api/v1/clients/me/roles/reader/permissions"),
    ] {
        let mut json = br#"{"permissions":[]}"#.to_vec();
        json.resize(2 * 1024 * 1024 + 1, b' ');
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
            .body(Body::from(json))
            .unwrap();
        let response = routes.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn role_permission_documents_validate_integer_size_before_authorization() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    for path in [
        "/api/v1/admin/clients/example/roles/reader/permissions",
        "/api/v1/clients/me/roles/reader/permissions",
    ] {
        let body = format!(r#"{{"permissions":[],"extra":{}}}"#, "9".repeat(4301));
        let request = Request::put(path)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
            .body(Body::from(body))
            .unwrap();
        let response = routes.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
    }
}

#[tokio::test]
async fn padded_product_writes_reach_administrator_authentication() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    let mut document = b"{}".to_vec();
    document.resize(2 * 1024 * 1024 + 1, b' ');
    for (method, path) in [
        (Method::POST, "/api/v1/admin/products"),
        (Method::PATCH, "/api/v1/admin/products/example"),
        (Method::POST, "/api/v1/admin/apple-products"),
        (Method::POST, "/api/v1/admin/google-products"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
            .body(Body::from(document.clone()))
            .unwrap();
        let response = routes.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn bodyless_product_methods_respond_before_the_upload_finishes() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap();
    let routes = pyloros::profile::routes(pool, false).unwrap();
    for (method, expected) in [
        (Method::DELETE, StatusCode::UNAUTHORIZED),
        (Method::PUT, StatusCode::METHOD_NOT_ALLOWED),
    ] {
        let (finish_upload, remaining_upload) = tokio::sync::oneshot::channel();
        let (drained, observed) = tokio::sync::oneshot::channel();
        let stream = futures_util::stream::once(async move {
            remaining_upload.await.unwrap();
            drained.send(()).unwrap();
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"unused"))
        });
        let request = Request::builder()
            .method(method)
            .uri("/api/v1/admin/products/example")
            .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
            .body(Body::from_stream(stream))
            .unwrap();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            routes.clone().oneshot(request),
        )
        .await
        .expect("method dispatch waited for the unused upload")
        .unwrap();
        assert_eq!(response.status(), expected);
        finish_upload.send(()).expect("upload stream was dropped");
        tokio::time::timeout(std::time::Duration::from_secs(2), observed)
            .await
            .expect("remaining upload was never drained")
            .unwrap();
    }
}
