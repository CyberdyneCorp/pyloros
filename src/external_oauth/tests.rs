use super::*;
use axum::body::to_bytes;

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
