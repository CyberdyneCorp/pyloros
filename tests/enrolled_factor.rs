use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::DateTime;
use pyloros::enrolled_factor::{FactorDecision, FactorVerifier};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn existing_enrollment_claims_follow_session_commit_and_rollback() {
    use FactorDecision::*;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE TEMP TABLE users (id uuid, is_active boolean, totp_enabled boolean,
         totp_secret_encrypted bytea, totp_last_used_step bigint);
         CREATE TEMP TABLE mfa_recovery_codes (user_id uuid, code_hash text, used_at timestamptz);",
    )
    .execute(&pool)
    .await
    .unwrap();
    let user = Uuid::new_v4();
    // Reference-encrypted RFC test seed. Both the plaintext and the master are test data.
    let blob = STANDARD
        .decode("SYIQDJVCrq0WqpIF21sKP1Wb/VubuAnp0drFffzSd2JUOxdxS9TN6OxLdvxl6T23x7+2SyeAclg7WcL0")
        .unwrap();
    sqlx::query("INSERT INTO users VALUES($1,true,true,$2,NULL)")
        .bind(user)
        .bind(&blob)
        .execute(&pool)
        .await
        .unwrap();
    let digest = format!("{:x}", Sha256::digest(b"abc-123"));
    sqlx::query("INSERT INTO mfa_recovery_codes VALUES($1,$2,NULL)")
        .bind(user)
        .bind(digest)
        .execute(&pool)
        .await
        .unwrap();
    let verifier = FactorVerifier::new("test-only-factor-master").unwrap();
    let time = DateTime::from_timestamp(59, 0).unwrap();
    for (code, decision, commit) in [
        ("287082", Totp, false),
        ("287082", Totp, true),
        ("287082", InvalidCode, true),
        ("ABC- 123", RecoveryCode, false),
        ("abc-123", RecoveryCode, true),
        ("abc-123", InvalidCode, true),
    ] {
        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            verifier.consume(&mut tx, user, code, time).await.unwrap(),
            decision
        );
        if commit {
            tx.commit().await.unwrap()
        } else {
            tx.rollback().await.unwrap()
        }
    }
    let wrong = FactorVerifier::new("other-key").unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert!(wrong.consume(&mut tx, user, "123456", time).await.is_err());
}
