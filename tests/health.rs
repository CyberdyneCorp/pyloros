use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

async fn get(app: &Router, path: &str) -> (u16, Value) {
    let response = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = to_bytes(response.into_body(), 8192).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn live_without_a_database() {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://localhost:1/unavailable")
        .unwrap();
    pool.close().await;
    let app = pyloros::router("test".into(), pool);
    let (status, body) = get(&app, "/api/v1/health").await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({"status":"healthy","version":env!("CARGO_PKG_VERSION"),"environment":"test"})
    );
    let (status, body) = get(&app, "/api/v1/health/ready").await;
    assert_eq!(status, 503);
    assert_eq!(body["database"], false);
    assert_eq!(body["migrations"], false);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run just test-db"]
async fn postgres_readiness() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    // Resolve only temporary objects, even when testing against a migrated database.
    sqlx::query("SET search_path TO pg_temp")
        .execute(&pool)
        .await
        .unwrap();
    let app = pyloros::router("test".into(), pool.clone());
    let path = "/api/v1/health/ready";
    let (status, body) = get(&app, path).await;
    assert_eq!(status, 503);
    assert_eq!(body["database"], true);
    sqlx::query("CREATE TEMP TABLE alembic_version(version_num text)")
        .execute(&pool)
        .await
        .unwrap();
    for revision in ["old", pyloros::SCHEMA_REVISION] {
        sqlx::query("DELETE FROM alembic_version")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO alembic_version VALUES ($1)")
            .bind(revision)
            .execute(&pool)
            .await
            .unwrap();
        let (status, body) = get(&app, path).await;
        let matched = revision == pyloros::SCHEMA_REVISION;
        assert_eq!(status, if matched { 200 } else { 503 });
        assert_eq!(body["migrations"], matched);
    }
    sqlx::query("INSERT INTO alembic_version VALUES ('another')")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(get(&app, path).await.0, 503);
}
