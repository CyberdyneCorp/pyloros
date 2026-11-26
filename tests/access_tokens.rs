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

    // With IAM unavailable, the assembled response still carries the session's access credential.
    sqlx::raw_sql("CREATE TEMP TABLE iam_identities(incompatible_column uuid);
        CREATE TEMP TABLE sessions(id uuid,user_id uuid,refresh_token_hash text,user_agent text,ip_address inet,
            expires_at timestamptz,auth_time timestamptz,amr text,created_at timestamptz,last_used_at timestamptz);
        CREATE TEMP TABLE refresh_tokens(jti uuid,session_id uuid,user_id uuid,issued_at timestamptz,
            expires_at timestamptz,scopes text,client_id text,resource text)")
        .execute(&mut *tx).await.unwrap();
    let settings = pyloros::grant_response::GrantSettings {
        access_lifetime: ttl,
        id_lifetime: Duration::minutes(10),
        admin_emails: policy.admin_emails,
        require_verified_admin_email: true,
        resources: policy.resources,
    };
    sqlx::query("CREATE TEMP TABLE auth_events(id uuid,subject_email text,details jsonb,content_hash text,request_id text)")
        .execute(&mut *tx).await.unwrap();
    use sqlx::Acquire;
    let mut grant_tx = tx.begin().await.unwrap();
    claimed.grant.scopes.clear();
    let response = issuer
        .issue_code_response(
            &mut grant_tx,
            &claimed,
            &settings,
            pyloros::grant_response::SessionOrigin {
                user_agent: None,
                ip: None,
            },
            Some("invalid correlation id"),
            now,
        )
        .await
        .unwrap();
    let body = serde_json::to_value(response).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 3);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 900);
    let signed = decode::<Value>(body["access_token"].as_str().unwrap(), &verify, &validation)
        .unwrap()
        .claims;
    assert_eq!(signed["sid"], claimed.session_id.to_string());
    assert!(signed.get("roles").is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM refresh_tokens WHERE session_id=$1")
            .bind(claimed.session_id)
            .fetch_one(&mut *grant_tx)
            .await
            .unwrap(),
        1
    );
    let event = sqlx::query_as::<_, (String, Value, String, Option<String>)>(
        "SELECT subject_email,details,content_hash,request_id FROM auth_events",
    )
    .fetch_one(&mut *grant_tx)
    .await
    .unwrap();
    assert_eq!(event.0, "owner@example.org");
    assert_eq!(
        event.1,
        json!({"grant_type":"authorization_code","session_id":claimed.session_id.to_string(),"scope":[]})
    );
    assert_eq!(event.2.len(), 64);
    assert!(event.3.is_none());
    grant_tx.rollback().await.unwrap();
    let counts = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT (SELECT count(*) FROM auth_events),
        (SELECT count(*) FROM sessions),(SELECT count(*) FROM refresh_tokens)",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(counts, (0, 0, 0));
}
