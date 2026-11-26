use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
    routing::get,
};
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use tower::ServiceExt;

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn registered_frontend_loses_access_after_deactivation() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE TEMP TABLE oauth_web_origins(origin text, active boolean, cors boolean);
        INSERT INTO oauth_web_origins VALUES ('https://admin.example.test',true,true),
            ('https://redirect.example.test',true,false)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let app = pyloros::cors::apply(
        Router::new().route("/", get(|| async { "healthy" })),
        pool.clone(),
        Duration::from_millis(30),
    )
    .await
    .unwrap();
    let check = |origin: &'static str| {
        app.clone().oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/")
                .header("origin", origin)
                .header("access-control-request-method", "POST")
                .header("access-control-request-headers", "X-CSRF-Token")
                .body(Body::empty())
                .unwrap(),
        )
    };
    let origin = "https://admin.example.test";
    let success = check(origin).await.unwrap();
    assert_eq!(success.status(), StatusCode::OK);
    assert_eq!(success.headers()["access-control-allow-origin"], origin);
    assert_eq!(
        success.headers()["access-control-allow-headers"],
        "X-CSRF-Token"
    );
    let redirect_only = check("https://redirect.example.test").await.unwrap();
    assert_eq!(redirect_only.status(), StatusCode::BAD_REQUEST);
    assert!(
        !redirect_only
            .headers()
            .contains_key("access-control-allow-origin")
    );
    sqlx::query("UPDATE oauth_web_origins SET active=false")
        .execute(&pool)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let response = check(origin).await.unwrap();
            if response.status() == StatusCode::BAD_REQUEST {
                assert!(
                    !response
                        .headers()
                        .contains_key("access-control-allow-origin")
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}
