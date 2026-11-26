use chrono::TimeDelta;
use pyloros::{
    email_challenge::{
        ConfirmationDecision, ConfirmationError, ConfirmationPolicy, require_if_due,
    },
    grant_response::SessionOrigin,
    signing::SigningIdentity,
};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn failed_delivery_leaves_only_a_failure_event() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TEMP TABLE users(id uuid,primary_email text,organization_id uuid,is_active boolean,totp_enabled boolean,last_magic_link_at timestamptz);
        CREATE TEMP TABLE auth_policy(id int,magic_link_interval_seconds int);
        CREATE TEMP TABLE magic_link_challenges(id uuid,user_id uuid,token_hash text,match_code text,status text,expires_at timestamptz,created_at timestamptz,created_ip text,created_user_agent text);
        CREATE TEMP TABLE auth_events(outcome text,reason_code text);").execute(&pool).await.unwrap();
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users VALUES ($1,'member@example.org',NULL,true,false,NULL)")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let signer = SigningIdentity::hmac("issuer".into(), b"fixture-key").unwrap();
    let policy = || ConfirmationPolicy {
        signer: &signer,
        lifetime: TimeDelta::minutes(5),
        origin: SessionOrigin {
            ip: None,
            user_agent: None,
        },
        request_id: None,
    };
    let decision = require_if_due(&pool, pool.begin().await.unwrap(), user, policy(), |_| {
        std::future::ready(Err::<(), _>(()))
    })
    .await
    .unwrap();
    let ConfirmationDecision::Continue(tx) = decision else {
        panic!("expected login to continue")
    };
    tx.rollback().await.unwrap();
    sqlx::query("INSERT INTO auth_policy VALUES(1,60)")
        .execute(&pool)
        .await
        .unwrap();
    let decision = require_if_due(
        &pool,
        pool.begin().await.unwrap(),
        user,
        policy(),
        |message| async move {
            assert_eq!(message.recipient, "member@example.org");
            assert_eq!(message.token.len(), 43);
            assert!((10..100).contains(&message.match_code.parse::<u32>().unwrap()));
            Err::<(), _>(())
        },
    )
    .await;
    assert!(matches!(decision, Err(ConfirmationError::Delivery)));
    let (remaining, outcome, reason) = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT (SELECT count(*) FROM magic_link_challenges),outcome,reason_code FROM auth_events",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (remaining, outcome.as_str(), reason.as_str()),
        (0, "failure", "provider_error")
    );
}
