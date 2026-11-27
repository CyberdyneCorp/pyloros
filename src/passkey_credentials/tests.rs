use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    id: String,
    key: String,
    handle: String,
    challenge: String,
    proof: serde_json::Value,
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn credential_usage_rolls_back_with_login_and_revocation_prevents_reuse() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TEMP TABLE users(id uuid, totp_enabled bool, primary_email text, organization_id uuid, is_active bool);
        CREATE TEMP TABLE passkeys(id uuid, user_id uuid, rp_id text, credential_id text, public_key bytea, sign_count bigint, backup_eligible bool, backed_up bool, last_used_at timestamptz, revoked_at timestamptz);
        CREATE TEMP TABLE passkey_handles(user_id uuid, handle bytea);").execute(&pool).await.unwrap();
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("../../tests/fixtures/passkey-assertions.json")).unwrap();
    let f = &fixtures[0];
    let user = Uuid::new_v4();
    let key = Uuid::new_v4();
    let binding = CeremonyBinding {
        relying_party: "example.test",
        origin: "https://keys.example.test",
        binding: "unused",
        policy_digest: "unused",
    };
    sqlx::query("INSERT INTO users VALUES ($1,false,NULL,NULL,true)")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO passkey_handles VALUES ($1,$2)")
        .bind(user)
        .bind(URL_SAFE_NO_PAD.decode(&f.handle).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO passkeys(id,user_id,rp_id,credential_id,public_key,sign_count,backup_eligible) VALUES ($1,$2,$3,$4,$5,0,false)")
        .bind(key).bind(user).bind(binding.relying_party).bind(&f.id).bind(URL_SAFE_NO_PAD.decode(&f.key).unwrap()).execute(&pool).await.unwrap();
    let challenge = URL_SAFE_NO_PAD.decode(&f.challenge).unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert!(matches!(
        authenticate(
            &mut tx,
            f.proof.clone(),
            &binding,
            challenge.clone(),
            Some(Uuid::new_v4())
        )
        .await
        .unwrap(),
        Err(AssertionError::Invalid)
    ));
    let owner = authenticate(
        &mut tx,
        f.proof.clone(),
        &binding,
        challenge.clone(),
        Some(user),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((owner.user, owner.key), (user, key));
    let usage = "SELECT sign_count, last_used_at IS NOT NULL FROM passkeys";
    assert_eq!(
        sqlx::query_as::<_, (i64, bool)>(usage)
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        (3, true)
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        sqlx::query_as::<_, (i64, bool)>(usage)
            .fetch_one(&pool)
            .await
            .unwrap(),
        (0, false)
    );
    sqlx::query("UPDATE passkeys SET revoked_at=now()")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert!(matches!(
        authenticate(&mut tx, f.proof.clone(), &binding, challenge, None)
            .await
            .unwrap(),
        Err(AssertionError::Invalid)
    ));
}
