use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
};
use pyloros::discovery::{Provider, routes};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn get(app: &Router, path: &str) -> (u16, Value) {
    let response = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = to_bytes(response.into_body(), 16384).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

const OIDC: &str = "/.well-known/openid-configuration";
const OAUTH: &str = "/.well-known/oauth-authorization-server";
const KEYS: &str = "/.well-known/jwks.json";
const PEM: &str = include_str!("fixtures/public.pem");

#[tokio::test]
async fn disabled_routes_report_the_same_error() {
    let app = routes(None);
    for path in [OIDC, OAUTH, KEYS] {
        assert_eq!(
            get(&app, path).await,
            (
                404,
                json!({"type":"about:blank","title":"OIDC disabled","status":404,"detail":"OIDC disabled"})
            )
        );
    }
}

#[tokio::test]
async fn issuer_scopes_and_optional_grants_follow_configuration() {
    for enabled in [false, true] {
        let provider = Provider::new(
            "https://auth.example/realm/",
            PEM,
            None,
            "profile openid profile",
            enabled,
            enabled,
        )
        .unwrap();
        let app = routes(Some(provider));
        let (status, doc) = get(&app, OIDC).await;
        assert_eq!(status, 200);
        assert_eq!(doc, get(&app, OAUTH).await.1);
        assert_eq!(doc["issuer"], "https://auth.example/realm");
        assert_eq!(doc["scopes_supported"], json!(["openid", "profile"]));
        assert_eq!(
            doc["jwks_uri"],
            "https://auth.example/realm/.well-known/jwks.json"
        );
        assert_eq!(doc.get("registration_endpoint").is_some(), enabled);
        assert_eq!(doc.get("device_authorization_endpoint").is_some(), enabled);
        assert_eq!(
            doc["grant_types_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "urn:ietf:params:oauth:grant-type:device_code"),
            enabled
        );
        let (status, keys) = get(&app, KEYS).await;
        assert_eq!(status, 200);
        let key = &keys["keys"][0];
        assert_eq!(key["e"], "AQAB");
        assert_eq!(key["kid"], "N1OHUndSZ2u6yAFTMa0LAXzLXnQ27FEqQfpGHsfSF-8");
        assert_eq!(key.as_object().unwrap().len(), 6);
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn postgres_scope_refresh() {
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::query("CREATE TEMP TABLE oauth_scopes(name text, active boolean, description text)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO oauth_scopes(name,active) VALUES ('openid',true),('extra',true),('hidden',false)")
        .execute(&pool)
        .await
        .unwrap();
    let mut provider =
        Provider::new("https://auth.example", PEM, None, "openid", false, false).unwrap();
    provider
        .refresh_scopes(pool.clone(), Duration::from_millis(25))
        .await;
    let app = routes(Some(provider));
    assert_eq!(
        get(&app, OIDC).await.1["scopes_supported"],
        json!(["extra", "openid"])
    );
    sqlx::query("UPDATE oauth_scopes SET active = NOT active")
        .execute(&pool)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if get(&app, OAUTH).await.1["scopes_supported"] == json!(["hidden", "openid"]) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    pool.close().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        get(&app, OIDC).await.1["scopes_supported"],
        json!(["hidden", "openid"])
    );
}
