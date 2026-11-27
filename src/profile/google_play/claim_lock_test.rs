//! A push must observe Play after an in-flight claim releases its purchase lock.
use super::*;
use tokio::sync::Notify;

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn purchase_lookup_holds_the_shared_transaction_lock() {
    let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let token = Uuid::new_v4().to_string();
    let arrived = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let lookup = {
        let arrived = arrived.clone();
        let release = release.clone();
        move || async move {
            arrived.notify_one();
            release.notified().await;
            StatusCode::NOT_FOUND
        }
    };
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(server, Router::new().fallback(lookup))
            .await
            .unwrap();
    });
    let cached = Client {
        http: reqwest::Client::new(),
        signing: EncodingKey::from_secret(b"unused-by-cached-token"),
        issuer: "test".into(),
        key_id: None,
        token: Mutex::new(Some((i64::MAX, Zeroizing::new("test".into())))),
        token_url: String::new(),
        play_url: format!("http://{address}"),
    };
    let provider = Provider {
        package: "example".into(),
        credentials: Zeroizing::new(String::new()),
        client: OnceCell::new_with(Some(cached)),
        push: None,
        store_slots: tokio::sync::Semaphore::new(3),
    };
    let claim = {
        let pool = pool.clone();
        let token = token.clone();
        tokio::spawn(async move {
            super::super::claim(&pool, Uuid::new_v4(), &token, "monthly", &provider, false)
                .await
                .unwrap()
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), arrived.notified())
        .await
        .unwrap();
    let try_lock = || {
        sqlx::query_scalar::<_, bool>(
            "SELECT pg_try_advisory_xact_lock(hashtext('google-purchase'),hashtext($1))",
        )
        .bind(&token)
        .fetch_one(&pool)
    };
    assert!(!try_lock().await.unwrap());
    release.notify_one();
    assert_eq!(claim.await.unwrap().status(), StatusCode::BAD_REQUEST);
    // SQLx queues rollback when a transaction is dropped. Wait for PostgreSQL
    // to release the lock before a second claimant proceeds.
    let acquire =
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('google-purchase'),hashtext($1))")
            .bind(&token)
            .execute(&pool);
    tokio::time::timeout(std::time::Duration::from_secs(5), acquire)
        .await
        .unwrap()
        .unwrap();
    server.abort();
}
