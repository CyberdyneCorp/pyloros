use super::*;
use axum::body::to_bytes;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn only_valid_cli_requests_persist_callback_state() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::query(
        "CREATE TEMP TABLE oauth_states(id uuid PRIMARY KEY, provider text,return_mode text,
        frontend_redirect text,expires_at timestamptz,cli_port int,code_challenge text)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let (_, allowed) = watch::channel(Redirects::new());
    let service = Arc::new(Service {
        pool: pool.clone(),
        providers: [("google", Provider::Stub("https://issuer.example/cb".into()))].into(),
        allowed,
        ttl: 60,
        cli: true,
        forbidden_stub: false,
    });
    let request = |query: String| {
        start(
            State(service.clone()),
            Path("google".into()),
            RawQuery(Some(query)),
            Method::GET,
        )
    };
    let invalid = request("return_mode=cli&cli_port=8000&code_challenge=oops".into()).await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let challenge = "a".repeat(43);
    let response = request(format!(
        "return_mode=cli&cli_port=8000&code_challenge={challenge}"
    ))
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 2048).await.unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let id = Uuid::parse_str(doc["state"].as_str().unwrap()).unwrap();
    let rows=sqlx::query_as::<_,(Uuid,String,String,i32,String,bool)>(
        "SELECT id,provider,return_mode,cli_port,code_challenge,
         frontend_redirect IS NULL AND expires_at BETWEEN now()+interval '55 seconds' AND now()+interval '61 seconds' FROM oauth_states"
    ).fetch_all(&pool).await.unwrap();
    assert_eq!(
        rows,
        [(id, "google".into(), "cli".into(), 8000, challenge, true)]
    );
    assert_eq!(
        doc["authorization_url"],
        format!("https://issuer.example/cb?code=stub-code&state={id}")
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn callback_claim_rolls_back_with_the_login_and_expires_before_reuse() {
    use super::state::{InvalidState, Pending, ReturnInstructions};
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::query("CREATE TEMP TABLE oauth_states(id uuid PRIMARY KEY,provider text,return_mode text,frontend_redirect text,expires_at timestamptz,cli_port int,code_challenge text,consumed_at timestamptz)").execute(&pool).await.unwrap();
    let instructions = ReturnInstructions {
        return_mode: "fragment".into(),
        frontend_redirect: Some("https://web.example/cb".into()),
        cli_port: None,
        code_challenge: None,
    };
    let id = instructions.issue(&pool, "google", 300).await.unwrap();
    let raw = id.to_string();
    let inspect = |provider| Pending::inspect(&pool, &raw, provider);
    assert_eq!(
        inspect("microsoft").await.unwrap(),
        Err(InvalidState::Provider)
    );
    let pending = inspect("google").await.unwrap().unwrap();
    assert_eq!(pending.instructions, instructions);
    let mut tx = pool.begin().await.unwrap();
    assert!(pending.claim(&mut tx).await.unwrap());
    tx.rollback().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert!(pending.claim(&mut tx).await.unwrap());
    tx.commit().await.unwrap();
    assert_eq!(
        inspect("google").await.unwrap(),
        Err(InvalidState::Consumed)
    );
    let mut tx = pool.begin().await.unwrap();
    assert!(!pending.claim(&mut tx).await.unwrap());
    tx.rollback().await.unwrap();
    sqlx::query("UPDATE oauth_states SET consumed_at=NULL,expires_at=now() WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(inspect("google").await.unwrap(), Err(InvalidState::Expired));
    let mut tx = pool.begin().await.unwrap();
    assert!(!pending.claim(&mut tx).await.unwrap());
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn concurrent_callback_transactions_have_one_winner() {
    use super::state::{Pending, ReturnInstructions};
    let database = env::var("DATABASE_URL").unwrap();
    let admin = PgPool::connect(&database).await.unwrap();
    let schema = format!("callback_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let search_path = format!("SET search_path TO {schema}");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _| {
            let query = search_path.clone();
            Box::pin(async move { sqlx::query(&query).execute(conn).await.map(|_| ()) })
        })
        .connect(&database)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE oauth_states(id uuid PRIMARY KEY,provider text,return_mode text,frontend_redirect text,expires_at timestamptz,cli_port int,code_challenge text,consumed_at timestamptz)").execute(&pool).await.unwrap();
    let instructions = ReturnInstructions {
        return_mode: "cookie".into(),
        frontend_redirect: None,
        cli_port: None,
        code_challenge: None,
    };
    let id = instructions.issue(&pool, "google", 60).await.unwrap();
    let pending = Pending::inspect(&pool, &id.to_string(), "google")
        .await
        .unwrap()
        .unwrap();
    let commit = || async {
        let mut tx = pool.begin().await.unwrap();
        let claimed = pending.claim(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
        claimed
    };
    let (one, two) = tokio::join!(commit(), commit());
    assert_ne!(one, two);
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}
