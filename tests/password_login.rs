use chrono::Duration;
use pyloros::{
    grant_response::SessionOrigin,
    mfa_challenges::ChallengeVerifier,
    password_login::{PasswordAttempt, PasswordDecision, evaluate},
    passwords::PasswordScheme,
    signing::SigningIdentity,
};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn enrolled_accounts_receive_only_a_challenge_after_password_validation() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TEMP TABLE users (id uuid,primary_email text,organization_id uuid,password_hash text,is_active boolean,totp_enabled boolean);
        CREATE TEMP TABLE auth_events(activity text,outcome text,reason_code text,subject_user_id uuid,details jsonb)")
        .execute(&pool).await.unwrap();
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users VALUES($1,'Member@example.org',NULL,$2,true,true)")
        .bind(user)
        .bind(bcrypt::hash("fixture", 4).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let signing = SigningIdentity::hmac("test".into(), b"fixture-key").unwrap();
    let attempt = |password: &str| PasswordAttempt {
        email: " member@EXAMPLE.org ",
        password: password.into(),
        origin: SessionOrigin {
            ip: None,
            user_agent: None,
        },
        request_id: None,
    };
    let decision = evaluate(
        &pool,
        PasswordScheme::Bcrypt,
        &signing,
        Duration::minutes(5),
        attempt("fixture"),
    )
    .await
    .unwrap();
    let PasswordDecision::Totp { token } = decision else {
        panic!("expected a second-factor challenge")
    };
    assert_eq!(
        ChallengeVerifier::hmac("test", b"fixture-key")
            .unwrap()
            .verify(&token)
            .unwrap()
            .user,
        user
    );
    let event = sqlx::query_as::<_, (String, String, String)>(
        "SELECT activity,outcome,reason_code FROM auth_events",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        event,
        (
            "mfa_challenge".into(),
            "success".into(),
            "mfa_required".into()
        )
    );
    sqlx::query("UPDATE users SET is_active=false")
        .execute(&pool)
        .await
        .unwrap();
    let bad = evaluate(
        &pool,
        PasswordScheme::Bcrypt,
        &signing,
        Duration::minutes(5),
        attempt("wrong"),
    )
    .await
    .unwrap();
    assert!(matches!(bad, PasswordDecision::InvalidCredentials));
    let inactive = evaluate(
        &pool,
        PasswordScheme::Bcrypt,
        &signing,
        Duration::minutes(5),
        attempt("fixture"),
    )
    .await
    .unwrap();
    assert!(matches!(inactive, PasswordDecision::Inactive));
}
