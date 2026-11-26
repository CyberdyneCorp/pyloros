use chrono::{Duration, Utc};
use pyloros::{
    code_decision::CodeDecision,
    code_exchange::ExchangeRequest,
    grant_response::{GrantSettings, SessionOrigin},
    grant_sessions::GrantSessionIssuer,
};
use rsa::pkcs8::EncodePrivateKey;
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn refusal_survives_unavailable_audit_storage() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::query(
        "CREATE TEMP TABLE auth_events(outcome text,reason_code text, subject_user_id uuid,
        client_id text, details jsonb, request_id text)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let issuer = GrantSessionIssuer::new(
        "issuer".into(),
        "key".into(),
        key.to_pkcs8_pem(Default::default()).unwrap().as_bytes(),
        Duration::days(1),
    )
    .unwrap();
    let settings = GrantSettings {
        access_lifetime: Duration::minutes(15),
        id_lifetime: Duration::minutes(10),
        admin_emails: &[],
        require_verified_admin_email: true,
        resources: &Default::default(),
    };
    let request = ExchangeRequest {
        client_id: "",
        client_secret: None,
        code: "",
        verifier: "",
        redirect_uri: None,
        resources: &[],
    };
    let origin = SessionOrigin {
        ip: None,
        user_agent: None,
    };
    for audit_available in [true, false] {
        if !audit_available {
            sqlx::query("ALTER TABLE pg_temp.auth_events ADD CONSTRAINT refuse_writes CHECK (false) NOT VALID")
                .execute(&pool).await.unwrap();
        }
        let result = issuer
            .exchange_code(&pool, &request, &settings, origin, Some("unit"), Utc::now())
            .await
            .unwrap();
        let CodeDecision::Refused(error) = result else {
            panic!("expected refusal")
        };
        assert_eq!(error.status(), 401);
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            serde_json::json!({"error":"invalid_client","error_description":"missing client_id"})
        );
    }
    let rows =
        sqlx::query_scalar::<_, serde_json::Value>("SELECT to_jsonb(e) FROM pg_temp.auth_events e")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        [
            serde_json::json!({"outcome":"failure","reason_code":"invalid_client",
        "subject_user_id":null,"client_id":null,"details":{"grant_type":"authorization_code"},"request_id":"unit"})
        ]
    );
}
