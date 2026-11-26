use chrono::{Duration, Utc};
use pyloros::authorization_codes::{Grant, find, issue};
use pyloros::code_exchange::{Exchange, ExchangeRequest, Refusal, redeem};
use pyloros::grant_sessions::GrantSessionIssuer;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
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
        challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
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
    sqlx::raw_sql(
        "CREATE TABLE oauth_clients(client_id text, client_type text, grant_types text, active boolean,
                   secret_hash text, previous_secret_hash text, previous_secret_expires_at timestamptz);
                   INSERT INTO oauth_clients(client_id, client_type, grant_types, active)
                   VALUES ('web','public','authorization_code',true),('other','public','authorization_code',true);
                   CREATE TABLE users(id uuid PRIMARY KEY, is_active boolean);
                   CREATE TABLE sessions(id uuid PRIMARY KEY, revoked_at timestamptz, user_id uuid, refresh_token_hash text, user_agent text, ip_address inet, expires_at timestamptz, auth_time timestamptz, amr text, created_at timestamptz, last_used_at timestamptz);
                   CREATE TABLE refresh_tokens(session_id uuid, revoked_at timestamptz, user_id uuid, jti uuid, issued_at timestamptz, expires_at timestamptz, scopes text, client_id text, resource text)",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("INSERT INTO users VALUES($1,false)")
        .bind(grant.user_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let now = Utc::now();
    let session = Uuid::new_v4();
    let request = ExchangeRequest {
        client_id: "web",
        client_secret: None,
        code: &code,
        redirect_uri: Some(&grant.redirect_uri),
        verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        resources: &[],
    };
    let different_resource = ["https://different.example".to_owned()];
    let repeated = [
        "https://api.example".to_owned(),
        "https://api.example".to_owned(),
    ];
    for (invalid, at, expected) in [
        (
            ExchangeRequest { ..request },
            now + Duration::hours(1),
            Refusal::Expired,
        ),
        (ExchangeRequest { ..request }, now, Refusal::UserUnavailable),
        (
            ExchangeRequest {
                client_id: "other",
                ..request
            },
            now,
            Refusal::UnknownCode,
        ),
        (
            ExchangeRequest {
                redirect_uri: None,
                ..request
            },
            now,
            Refusal::RedirectMismatch,
        ),
        (
            ExchangeRequest {
                resources: &different_resource,
                ..request
            },
            now,
            Refusal::InvalidTarget,
        ),
        (
            ExchangeRequest {
                resources: &repeated,
                ..request
            },
            now,
            Refusal::InvalidTarget,
        ),
        (
            ExchangeRequest {
                verifier: "different",
                ..request
            },
            now,
            Refusal::InvalidProof,
        ),
        (
            ExchangeRequest {
                verifier: "",
                ..request
            },
            now,
            Refusal::MissingVerifier,
        ),
        (
            ExchangeRequest {
                code: "",
                ..request
            },
            now,
            Refusal::MissingCode,
        ),
    ] {
        let Exchange::Refused(reason) = redeem(&mut tx, &invalid, session, at).await.unwrap()
        else {
            panic!("invalid grant was accepted")
        };
        assert_eq!(reason, expected);
    }
    sqlx::query("UPDATE users SET is_active=true")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let pem = key.to_pkcs8_pem(Default::default()).unwrap();
    let issuer = GrantSessionIssuer::new(
        "https://issuer.example".into(),
        "test".into(),
        pem.as_bytes(),
        Duration::days(30),
    )
    .unwrap();
    let mut aborted = transaction(&pool, &namespace).await;
    let Exchange::Granted(attempt) = redeem(&mut aborted, &request, session, now).await.unwrap()
    else {
        panic!("valid grant refused")
    };
    assert!(
        issuer
            .create(&mut aborted, &attempt, now, None, None)
            .await
            .unwrap()
            .is_none()
    );
    let offline_session = Uuid::new_v4();
    let offline_grant = Grant {
        scopes: "openid offline_access".into(),
        ..attempt.grant
    };
    let offline_code = issue(&mut aborted, &offline_grant).await.unwrap();
    let offline_request = ExchangeRequest {
        code: &offline_code,
        ..request
    };
    let Exchange::Granted(offline) = redeem(&mut aborted, &offline_request, offline_session, now)
        .await
        .unwrap()
    else {
        panic!("offline grant refused")
    };
    let token = issuer
        .create(&mut aborted, &offline, now, None, None)
        .await
        .unwrap()
        .unwrap();
    let public_pem = key
        .to_public_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    let verify_key = jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&["https://issuer.example"]);
    let signed =
        jsonwebtoken::decode::<serde_json::Value>(&token, &verify_key, &validation).unwrap();
    assert_eq!(signed.header.kid.as_deref(), Some("test"));
    assert_eq!(signed.claims["sid"], offline_session.to_string());
    assert_eq!(signed.claims["type"], "refresh");
    let jti: Uuid = signed.claims["jti"].as_str().unwrap().parse().unwrap();
    let scopes: String = sqlx::query_scalar("SELECT scopes FROM refresh_tokens WHERE jti=$1")
        .bind(jti)
        .fetch_one(&mut *aborted)
        .await
        .unwrap();
    assert_eq!(scopes, "offline_access openid");
    aborted.rollback().await.unwrap();

    let mut winner = transaction(&pool, &namespace).await;
    let mut contender = transaction(&pool, &namespace).await;
    let resource_claim = ["https://api.example".to_owned()];
    let approved = ExchangeRequest {
        resources: &resource_claim,
        ..request
    };
    let Exchange::Granted(actual) = redeem(&mut winner, &approved, session, now).await.unwrap()
    else {
        panic!("valid grant refused")
    };
    assert_eq!(actual.grant.user_id, grant.user_id);
    assert!(
        issuer
            .create(
                &mut winner,
                &actual,
                now,
                Some("test-agent"),
                Some("::1".parse().unwrap())
            )
            .await
            .unwrap()
            .is_none()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE session_id=$1")
        .bind(session)
        .fetch_one(&mut *winner)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let other_session = Uuid::new_v4();
    sqlx::query("INSERT INTO refresh_tokens(session_id) VALUES ($1),($2)")
        .bind(session)
        .bind(other_session)
        .execute(&mut *winner)
        .await
        .unwrap();
    let (lost, committed) = tokio::join!(
        redeem(&mut contender, &request, Uuid::new_v4(), now),
        winner.commit()
    );
    committed.unwrap();
    assert!(matches!(
        lost.unwrap(),
        Exchange::Refused(Refusal::Replayed)
    ));
    let replay = find(&mut contender, &code, "web").await.unwrap().unwrap();
    assert!(replay.consumed_at.is_some());
    assert_eq!(replay.session_id, Some(session));
    contender.commit().await.unwrap();
    let mut verify = transaction(&pool, &namespace).await;
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM sessions WHERE id=$1")
            .bind(session)
            .fetch_one(&mut *verify)
            .await
            .unwrap();
    assert!(revoked);
    let live: Vec<Uuid> =
        sqlx::query_scalar("SELECT session_id FROM refresh_tokens WHERE revoked_at IS NULL")
            .fetch_all(&mut *verify)
            .await
            .unwrap();
    assert_eq!(live, vec![other_session]);
    verify.commit().await.unwrap();
    sqlx::query(&format!("DROP SCHEMA {namespace} CASCADE"))
        .execute(&pool)
        .await
        .unwrap();
}
