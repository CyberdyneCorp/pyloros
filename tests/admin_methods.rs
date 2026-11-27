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
