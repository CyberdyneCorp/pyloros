use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use pyloros::{
    access_tokens::AccessPolicy,
    authorization_codes::Grant,
    code_exchange::ClaimedGrant,
    grant_sessions::{GrantSessionIssuer, SessionError},
    id_tokens::{Assignments, AuthorizationClaims},
};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use serde_json::{Value, json};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn grant_access_claims() {
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql("CREATE TEMP TABLE users(id uuid,primary_email text,is_admin boolean,is_email_verified boolean,is_active boolean,organization_id uuid);
        CREATE TEMP TABLE organizations(id uuid,name text,short_name text,github_login text,is_active boolean);
        CREATE TEMP TABLE user_organizations(user_id uuid,organization_id uuid);
        CREATE TEMP TABLE entitlements(user_id uuid,organization_id uuid,status text,expires_at timestamptz,product_key text,plan text);
        CREATE TEMP TABLE oauth_clients(client_id text,active boolean,access_token_audience text);
        INSERT INTO oauth_clients VALUES ('app',true,NULL)").execute(&mut *tx).await.unwrap();
    let org = Uuid::new_v4();
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users VALUES ($1,'owner@example.org',false,false,true,$2)")
        .bind(user)
        .bind(org)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations VALUES ($1,'Example',NULL,'example',true)")
        .bind(org)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_organizations VALUES ($1,$2)")
        .bind(user)
        .bind(org)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO entitlements VALUES ($1,NULL,'active',NULL,'package','pro'),(NULL,$2,'active',NULL,'package','pro'),
        (NULL,$2,'active',NULL,'docs',NULL),($1,NULL,'revoked',NULL,'void',NULL),($1,NULL,'active',now()-interval '1 day','old',NULL)").bind(user).bind(org).execute(&mut *tx).await.unwrap();
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let issuer = GrantSessionIssuer::new(
        "https://issuer.example".into(),
        "test".into(),
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
    let now = Utc::now();
    let mut claimed = ClaimedGrant {
        session_id: Uuid::new_v4(),
        grant: Grant {
            client_id: "app".into(),
            user_id: user,
            scopes: "profile openid profile".into(),
            challenge: String::new(),
            redirect_uri: String::new(),
            nonce: Some("n".into()),
            resource: Some("resource".into()),
            expires_at: now,
            auth_time: None,
            amr: None,
        },
    };
    let roles = AuthorizationClaims {
        roles: Assignments {
            global: vec!["app:operator".into()],
            ..Default::default()
        },
        permissions: Some(Assignments::default()),
    };
    let mut policy = AccessPolicy {
        admin_emails: &[" OWNER@example.org ".into()],
        require_verified_admin_email: true,
        resources: &[("resource".into(), Some("api".into()))].into(),
        authorization: Some(&roles),
    };
    let ttl = Duration::minutes(15);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["api"]);
    validation.set_issuer(&["https://issuer.example"]);
    let token = issuer
        .issue_access_token(&mut tx, &claimed, &policy, now, ttl)
        .await
        .unwrap();
    let payload = decode::<Value>(&token, &verify, &validation)
        .unwrap()
        .claims;
    assert_eq!(payload["type"], "access");
    assert_eq!(payload["client_id"], "app");
    assert_eq!(payload["scope"], "openid profile");
    assert_eq!(payload["is_admin"], false);
    assert_eq!(payload["entitlements"], json!(["docs", "package:pro"]));
    assert_eq!(
        payload["org"],
        json!({"id":org.to_string(),"short_name":"Example"})
    );
    assert_eq!(
        payload["orgs"],
        json!([{"id":org.to_string(),"short_name":"Example","github_login":"example"}])
    );
    assert_eq!(payload["roles"], json!(["app:operator"]));
    assert_eq!(payload["permissions"], json!([]));
    assert!(payload.get("nonce").is_none());
    claimed.grant.resource = Some("removed".into());
    assert!(matches!(
        issuer
            .issue_access_token(&mut tx, &claimed, &policy, now, ttl)
            .await,
        Err(SessionError::UnknownResource)
    ));
    claimed.grant.resource = None;
    policy.authorization = None;
    sqlx::query("UPDATE organizations SET is_active=false")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET is_email_verified=true")
        .execute(&mut *tx)
        .await
        .unwrap();
    let token = issuer
        .issue_access_token(&mut tx, &claimed, &policy, now, ttl)
        .await
        .unwrap();
    validation.aud = None;
    let payload = decode::<Value>(&token, &verify, &validation)
        .unwrap()
        .claims;
    assert_eq!(payload["is_admin"], true);
    assert_eq!(payload["orgs"], json!([]));
    assert_eq!(payload["entitlements"], json!(["package:pro"]));
    for missing in [
        "aud",
        "org",
        "roles",
        "permissions",
        "org_roles",
        "org_permissions",
    ] {
        assert!(payload.get(missing).is_none());
    }
}
