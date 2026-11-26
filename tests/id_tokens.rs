use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use pyloros::{
    authorization_codes::Grant,
    code_exchange::ClaimedGrant,
    grant_sessions::GrantSessionIssuer,
    id_tokens::{Assignments, AuthorizationClaims},
};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use serde_json::{Value, json};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn signed_claims_follow_grant_and_audience() {
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("CREATE TEMP TABLE users(id uuid,primary_email text,is_email_verified bool,extra_metadata jsonb)").execute(&mut *tx).await.unwrap();
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users VALUES ($1,'a@example.org',false,$2)")
        .bind(user)
        .bind(json!({"name":"","full_name":"Alice","picture":"pic","avatar_url":"other"}))
        .execute(&mut *tx)
        .await
        .unwrap();
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let issuer = GrantSessionIssuer::new(
        "https://issuer.example".into(),
        "key1".into(),
        key.to_pkcs8_pem(Default::default()).unwrap().as_bytes(),
        Duration::days(30),
    )
    .unwrap();
    let verify = DecodingKey::from_rsa_pem(
        key.to_public_key()
            .to_public_key_pem(Default::default())
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["client"]);
    validation.set_issuer(&["https://issuer.example"]);
    let now = Utc::now();
    let mut claimed = ClaimedGrant {
        session_id: Uuid::new_v4(),
        grant: Grant {
            client_id: "client".into(),
            user_id: user,
            scopes: "email profile".into(),
            redirect_uri: String::new(),
            challenge: String::new(),
            expires_at: now,
            nonce: Some("challenge".into()),
            resource: Some("https://api.example".into()),
            auth_time: Some(now - Duration::hours(1)),
            amr: Some("pwd otp pwd".into()),
        },
    };
    let roles = AuthorizationClaims {
        roles: Assignments {
            global: vec!["client:editor".into(), "client2:owner".into()],
            organizations: [
                ("ours".into(), vec!["client:viewer".into()]),
                ("theirs".into(), vec!["client2:admin".into()]),
            ]
            .into(),
        },
        permissions: Some(Assignments::default()),
    };
    let ttl = Duration::minutes(15);
    assert!(
        issuer
            .issue_id_token(&mut tx, &claimed, Some(&roles), now, ttl)
            .await
            .unwrap()
            .is_none()
    );
    claimed.grant.scopes = "openid email profile roles".into();
    let token = issuer
        .issue_id_token(&mut tx, &claimed, Some(&roles), now, ttl)
        .await
        .unwrap()
        .unwrap();
    let signed = decode::<Value>(&token, &verify, &validation).unwrap();
    assert_eq!(signed.header.kid.as_deref(), Some("key1"));
    assert_eq!(
        signed.claims,
        json!({
            "iss":"https://issuer.example","sub":user.to_string(),"aud":"client","iat":now.timestamp(),"exp":(now+ttl).timestamp(),
            "auth_time":(now-Duration::hours(1)).timestamp(),"amr":["otp","pwd"],"nonce":"challenge","name":"Alice","picture":"pic",
            "email":"a@example.org","email_verified":false,"roles":["editor"],"org_roles":{"ours":["viewer"]},"permissions":[],"org_permissions":{}
        })
    );
    claimed.grant.auth_time = None;
    claimed.grant.nonce = None;
    for (scopes, assignments) in [("openid roles", None), ("openid", Some(&roles))] {
        claimed.grant.scopes = scopes.into();
        let token = issuer
            .issue_id_token(&mut tx, &claimed, assignments, now, ttl)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode::<Value>(&token, &verify, &validation)
                .unwrap()
                .claims,
            json!({
                "iss":"https://issuer.example","sub":user.to_string(),"aud":"client","iat":now.timestamp(),"exp":(now+ttl).timestamp()
            })
        );
    }
}
