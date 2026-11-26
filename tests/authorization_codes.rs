use chrono::{Duration, Utc};
use pyloros::authorization_codes::{Grant, claim, find, issue};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

async fn transaction<'a>(pool: &'a PgPool, namespace: &str) -> Transaction<'a, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('search_path',$1,true)")
        .bind(namespace)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn competing_exchanges_and_rollback() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let namespace = format!("code_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {namespace}"))
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = transaction(&pool, &namespace).await;
    sqlx::query(
        "CREATE TABLE oidc_authorization_codes (id uuid PRIMARY KEY, code_hash text UNIQUE,
        client_id text, user_id uuid, redirect_uri text, scopes text, code_challenge text,
        code_challenge_method text, expires_at timestamptz, nonce text, resource text,
        auth_time timestamptz, amr text, consumed_at timestamptz, session_id uuid)",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    let grant = Grant {
        client_id: "web".into(),
        user_id: Uuid::new_v4(),
        redirect_uri: "https://app.example/cb".into(),
        scopes: "openid profile".into(),
        challenge: "challenge".into(),
        expires_at: Utc::now() + Duration::minutes(1),
        nonce: Some("nonce".into()),
        resource: Some("https://api.example".into()),
        auth_time: None,
        amr: None,
    };
    let code = issue(&mut tx, &grant).await.unwrap();
    assert!(find(&mut tx, &code, "other").await.unwrap().is_none());
    let stored = find(&mut tx, &code, "web").await.unwrap().unwrap();
    assert_eq!(stored.grant.user_id, grant.user_id);
    assert_eq!(stored.grant.resource, grant.resource);
    assert_eq!(stored.challenge_method, "S256");
    tx.commit().await.unwrap();

    let mut aborted = transaction(&pool, &namespace).await;
    assert!(
        claim(&mut aborted, stored.id, Uuid::new_v4())
            .await
            .unwrap()
    );
    aborted.rollback().await.unwrap();

    let mut winner = transaction(&pool, &namespace).await;
    let mut contender = transaction(&pool, &namespace).await;
    let session = Uuid::new_v4();
    assert!(claim(&mut winner, stored.id, session).await.unwrap());
    let (lost, committed) = tokio::join!(
        claim(&mut contender, stored.id, Uuid::new_v4()),
        winner.commit()
    );
    committed.unwrap();
    assert!(!lost.unwrap());
    let replay = find(&mut contender, &code, "web").await.unwrap().unwrap();
    assert!(replay.consumed_at.is_some());
    assert_eq!(replay.session_id, Some(session));
    contender.rollback().await.unwrap();
    sqlx::query(&format!("DROP SCHEMA {namespace} CASCADE"))
        .execute(&pool)
        .await
        .unwrap();
}
