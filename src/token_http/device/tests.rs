use super::*;
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_device_code_becomes_pollable_only_when_its_audit_record_commits() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::raw_sql("
        CREATE TEMP TABLE oauth_clients (
            client_id text, active boolean, client_type text, grant_types text, allowed_scopes text,
            registration_source text, secret_hash text, previous_secret_expires_at timestamptz, previous_secret_hash text
        );
        CREATE TEMP TABLE device_authorizations (
            id uuid, device_code_hash text unique, user_code text unique, client_id text, scopes text, status text,
            interval_seconds int, created_at timestamptz, expires_at timestamptz
        );
        CREATE TEMP TABLE auth_events(activity text, details jsonb, CONSTRAINT audit_off CHECK(false));
    ").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO oauth_clients (client_id,active,client_type,grant_types,allowed_scopes,registration_source)
        VALUES ('device',true,'public',$1,'openid profile','admin')")
        .bind(GRANT).execute(&pool).await.unwrap();

    let state = Device {
        pool: pool.clone(),
        uri: "https://issuer.example/device".into(),
        lifetime: 90,
        interval: 3,
        quota: LoginThrottle::new(10),
        proxies: 0,
    };
    let issue = || {
        state.issue(
            Input {
                client: "device",
                secret: None,
                scope: "profile openid profile",
                resource: false,
            },
            SessionOrigin {
                ip: None,
                user_agent: None,
            },
            None,
        )
    };
    assert!(issue().await.is_err());
    let count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM device_authorizations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::query("ALTER TABLE auth_events DROP CONSTRAINT audit_off")
        .execute(&pool)
        .await
        .unwrap();

    let (status, body) = issue().await.unwrap();
    assert_eq!(status, StatusCode::OK);
    let raw = body["device_code"].as_str().unwrap();
    assert_eq!(URL_SAFE_NO_PAD.decode(raw).unwrap().len(), 32);
    let row = sqlx::query(
        "SELECT user_code,scopes,status,interval_seconds,
            extract(epoch from expires_at-created_at)::int as lifetime
        FROM device_authorizations WHERE device_code_hash=$1",
    )
    .bind(crate::authorization_codes::digest(raw))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row.get::<&str, _>("user_code"),
        body["user_code"].as_str().unwrap().replace('-', "")
    );
    assert_eq!(row.get::<&str, _>("scopes"), "openid profile");
    assert_eq!(row.get::<&str, _>("status"), "pending");
    assert_eq!(row.get::<i32, _>("interval_seconds"), 3);
    assert_eq!(row.get::<i32, _>("lifetime"), 90);
    let details = sqlx::query_scalar::<_, Value>(
        "SELECT details FROM auth_events WHERE activity='device_authorize'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        details,
        json!({"scope":["openid","profile"],"expires_in":90})
    );
}
