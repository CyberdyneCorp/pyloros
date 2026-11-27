use super::*;
use sqlx::PgPool;

const TABLES: &str = "CREATE TEMP TABLE users(id uuid PRIMARY KEY,primary_email text UNIQUE,is_active bool DEFAULT true,
        is_email_verified bool DEFAULT false, default_wallet_address text,public_key text,encrypted_private_key bytea,
        organization_id uuid,extra_metadata jsonb DEFAULT '{}',password_hash text,totp_enabled bool,totp_secret_encrypted bytea,updated_at timestamptz);
        CREATE TEMP TABLE user_identities(id uuid,user_id uuid,type text,provider text,identifier text,extra_data jsonb,UNIQUE(type,provider,identifier));
        CREATE TEMP TABLE organizations(id uuid,domain_name text,is_active bool);
        CREATE TEMP TABLE user_organizations(user_id uuid,organization_id uuid,UNIQUE(user_id,organization_id));
        CREATE TEMP TABLE sessions(user_id uuid,revoked_at timestamptz);
        CREATE TEMP TABLE mfa_recovery_codes(user_id uuid);";

async fn pool() -> PgPool {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::raw_sql(TABLES).execute(&pool).await.unwrap();
    pool
}

fn provider_profile() -> Profile {
    Profile {
        provider: "google",
        subject: "provider-subject".into(),
        email: Some("  Owner@Example.test ".into()),
        email_verified: true,
        name: Some("Owner".into()),
        picture: Some("https://example.test/photo".into()),
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn existing_subject_keeps_account_and_wallet_when_provider_email_changes() {
    let pool = pool().await;
    let key = KeyEncryptionKey::new("test").unwrap();
    let mut tx = pool.begin().await.unwrap();
    let mut identity = provider_profile();
    let org = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations VALUES($1,'example.test',true)")
        .bind(org)
        .execute(&mut *tx)
        .await
        .unwrap();
    let first = resolve(&mut tx, &identity, &key, false).await.unwrap();
    assert!(first.created);
    let row=sqlx::query_as::<_,(String,Uuid,String,Vec<u8>)>("SELECT primary_email,organization_id,default_wallet_address,encrypted_private_key FROM users WHERE id=$1")
        .bind(first.user).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(row.0, "owner@example.test");
    assert_eq!(row.1, org);
    assert_eq!(key.decrypt(&row.3).unwrap().len(), 32);
    identity.email = Some("changed@example.test".into());
    identity.email_verified = false;
    identity.picture = Some("https://example.test/new".into());
    let second = resolve(&mut tx, &identity, &key, false).await.unwrap();
    assert!(!second.created);
    assert_eq!(first.user, second.user);
    let current=sqlx::query_as::<_,(String,String,String)>("SELECT primary_email,default_wallet_address,extra_metadata->>'avatar_url' FROM users WHERE id=$1")
        .bind(first.user).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(current, (row.0, row.2, identity.picture.unwrap()));
    sqlx::query("UPDATE users SET is_active=false WHERE id=$1")
        .bind(first.user)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        matches!(resolve(&mut tx,&provider_profile(),&key,false).await,Err(AccountError::Inactive(id)) if id==first.user)
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn linking_a_verified_address_reclaims_only_the_unverified_account() {
    let pool = pool().await;
    let key = KeyEncryptionKey::new("test").unwrap();
    let mut tx = pool.begin().await.unwrap();
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,primary_email,password_hash,totp_enabled,totp_secret_encrypted) VALUES($1,'Owner@Example.Test','old',true,'seed')")
        .bind(user).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO sessions VALUES($1,NULL)")
        .bind(user)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mfa_recovery_codes VALUES($1)")
        .bind(user)
        .execute(&mut *tx)
        .await
        .unwrap();
    let mut profile = provider_profile();
    profile.email_verified = false;
    assert!(
        matches!(resolve(&mut tx,&profile,&key,false).await,Err(AccountError::UnverifiedEmail(email)) if email=="owner@example.test")
    );
    profile.email_verified = true;
    let result = resolve(&mut tx, &profile, &key, false).await.unwrap();
    assert!(!result.created);
    assert_eq!(result.user, user);
    assert!(sqlx::query_scalar::<_,bool>("SELECT is_email_verified AND password_hash IS NULL AND NOT totp_enabled AND totp_secret_encrypted IS NULL
        AND NOT EXISTS(SELECT FROM sessions WHERE revoked_at IS NULL) AND NOT EXISTS(SELECT FROM mfa_recovery_codes)
        AND (SELECT count(*)=1 FROM user_identities) FROM users WHERE id=$1")
        .bind(user).fetch_one(&mut *tx).await.unwrap());
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn concurrent_first_sign_ins_converge_on_one_account() {
    let url = std::env::var("DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("identity_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let path = format!("SET search_path TO {schema}");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _| {
            let sql = path.clone();
            Box::pin(async move { sqlx::query(&sql).execute(conn).await.map(|_| ()) })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::raw_sql(&TABLES.replace("CREATE TEMP TABLE", "CREATE TABLE"))
        .execute(&pool)
        .await
        .unwrap();
    let key = KeyEncryptionKey::new("local").unwrap();
    let login = |profile: Profile| {
        let pool = &pool;
        let key = &key;
        async move {
            let mut tx = pool.begin().await.unwrap();
            let account = resolve(&mut tx, &profile, key, false).await.unwrap();
            tx.commit().await.unwrap();
            account
        }
    };
    let (a, b) = tokio::join!(login(provider_profile()), login(provider_profile()));
    assert_eq!(a.user, b.user);
    assert_ne!(a.created, b.created);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_identities")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    let mut one = provider_profile();
    one.email = Some("other@example.test".into());
    one.subject = "new-google".into();
    let mut two = provider_profile();
    two.email = one.email.clone();
    two.provider = "microsoft";
    let (a, b) = tokio::join!(login(one), login(two));
    assert_eq!(a.user, b.user);
    assert_ne!(a.created, b.created);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_identities")
            .fetch_one(&pool)
            .await
            .unwrap(),
        3
    );
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}
