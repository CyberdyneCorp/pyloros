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
    assert_eq!(
        body["detail"],
        "migration state unreadable: ProgrammingError"
    );
    sqlx::query("CREATE TEMP TABLE alembic_version(version_num text)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO alembic_version VALUES (NULL)")
        .execute(&pool)
        .await
        .unwrap();
    let (_, body) = get(&app, path).await;
    assert_eq!(
        body["detail"],
        format!("schema at None, expected '{}'", pyloros::SCHEMA_REVISION)
    );
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
    let (status, body) = get(&app, path).await;
    assert_eq!(status, 503);
    assert_eq!(
        body["detail"],
        "migration state unreadable: MultipleResultsFound"
    );
}

#[tokio::test]
async fn foundation_routes_reject_head_and_post_before_running_get() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost:1/unavailable")
        .unwrap();
    pool.close().await;
    let app = pyloros::router("test".into(), pool).merge(pyloros::discovery::routes(None));
    for path in [
        "/api/v1/health",
        "/api/v1/health/ready",
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        for method in ["HEAD", "POST"] {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), 405, "{method} {path}");
            assert_eq!(res.headers()["allow"], "GET");
            let body = to_bytes(res.into_body(), 2048).await.unwrap();
            if method == "HEAD" {
                assert!(body.is_empty());
            } else {
                assert_eq!(
                    serde_json::from_slice::<Value>(&body).unwrap()["detail"],
                    "Method Not Allowed"
                );
            }
        }
    }
}

#[tokio::test]
async fn trailing_slash_redirects_preserve_query_and_method() {
    let app = pyloros::discovery::routes(None);
    let request = Request::post("/.well-known/jwks.json/?name=a%20b&v=2")
        .header("host", "auth.example:8443")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), 307);
    assert_eq!(
        response.headers()["location"],
        "http://auth.example:8443/.well-known/jwks.json?name=a%20b&v=2"
    );
}

#[tokio::test]
async fn refused_listener_is_identified_after_pool_retries() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy(&format!("postgres://user@{addr}/db"))
        .unwrap();
    let (status, body) = get(
        &pyloros::router("test".into(), pool),
        "/api/v1/health/ready",
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(
        body["detail"],
        "database unreachable: ConnectionRefusedError"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run just test-db"]
async fn readiness_waits_for_capacity_and_for_the_revision_query() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(250))
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut held = pool.acquire().await.unwrap();
    sqlx::query(
        "CREATE TEMP VIEW alembic_version AS SELECT '0043'::text AS version_num FROM pg_sleep(2.2)",
    )
    .execute(&mut *held)
    .await
    .unwrap();
    let app = pyloros::router("test".into(), pool);
    let check = get(&app, "/api/v1/health/ready");
    let release = async move {
        tokio::time::sleep(Duration::from_millis(550)).await;
        drop(held);
    };
    let ((status, body), ()) = tokio::join!(check, release);
    assert_eq!(status, 200, "{body}");
}

#[test]
#[ignore = "requires a writable PostgreSQL primary"]
fn writer_mode_observes_connection_options() {
    let mut url = url::Url::parse(&std::env::var("DATABASE_URL").unwrap()).unwrap();
    for (read_only, expected, code) in [
        (false, "writable primary", 0),
        (true, "read-only primary", 2),
    ] {
        if read_only {
            url.query_pairs_mut()
                .append_pair("options", "-c default_transaction_read_only=on");
        }
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_pyloros"))
            .arg("--check-db-writer-mode")
            .env("DATABASE_URL", url.as_str())
            .env("BIND_ADDR", "invalid")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(code));
        assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), expected);
    }
}
