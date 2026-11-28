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
        providers: [("google", Provider::test_google("https://issuer.example/cb"))].into(),
        allowed,
        ttl: 60,
        cli: true,
        forbidden_stub: false,
        login: None,
        wallet_key: None,
        post_login: None,
        proxies: 0,
        webhooks: false,
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
    for (port, status) in [
        ("0-_2", StatusCode::BAD_REQUEST),
        ("0__65536", StatusCode::BAD_REQUEST),
        ("9__001", StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let query =
            format!("return_mode=cli&cli_port=8000&cli_port={port}&code_challenge={challenge}");
        assert_eq!(request(query).await.status(), status, "{port}");
    }
    let response = request(format!(
        "return_mode=cli&cli_port=invalid&cli_port=%2B00__8000.00&code_challenge={challenge}"
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

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn cli_return_commits_a_short_lived_digest_with_the_callback_claim() {
    use state::{Pending, ReturnInstructions};
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TEMP TABLE oauth_states(id uuid PRIMARY KEY,provider text,return_mode text,frontend_redirect text,expires_at timestamptz,cli_port int,code_challenge text,consumed_at timestamptz);
        CREATE TEMP TABLE cli_login_codes(id uuid,code_hash text,user_id uuid,provider text,code_challenge text,authenticated_at timestamptz,expires_at timestamptz);").execute(&pool).await.unwrap();
    let instructions = ReturnInstructions {
        return_mode: "cli".into(),
        frontend_redirect: None,
        cli_port: Some(4555),
        code_challenge: Some("a".repeat(43)),
    };
    let id = instructions.issue(&pool, "microsoft", 600).await.unwrap();
    let pending = Pending::inspect(&pool, &id.to_string(), "microsoft")
        .await
        .unwrap()
        .unwrap();
    let user = Uuid::new_v4();
    let now = chrono::Utc::now();
    for commit in [false, true] {
        let mut tx = pool.begin().await.unwrap();
        assert!(pending.claim(&mut tx).await.unwrap());
        let target = cli_return::issue(&mut tx, &pending, user, now)
            .await
            .unwrap();
        let code = target
            .strip_prefix("http://127.0.0.1:4555/callback?code=")
            .unwrap();
        assert_eq!(code.len(), 43);
        let matches=sqlx::query_scalar::<_,bool>("SELECT code_hash=$1 AND user_id=$2 AND code_challenge=$3 AND provider='microsoft' AND expires_at-authenticated_at=interval '60 seconds' FROM cli_login_codes")
            .bind(crate::authorization_codes::digest(code)).bind(user).bind(&instructions.code_challenge).fetch_all(&mut *tx).await.unwrap();
        assert_eq!(matches, [true]);
        if commit {
            tx.commit().await.unwrap()
        } else {
            tx.rollback().await.unwrap()
        }
    }
}
