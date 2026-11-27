//! Public password registration on the shared account schema.
pub(super) mod admin;
pub(super) mod bulk;
use super::*;
use crate::{
    authorization_codes::digest,
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    key_encryption::KeyEncryptionKey,
    login_http::problem,
    login_throttle::{LoginThrottle, RateLimited},
    managed_wallet::ManagedWallet,
    token_http::{client_ip, header as value},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};

pub(super) struct Settings {
    key: Option<KeyEncryptionKey>,
    quota: LoginThrottle,
    hooks: bool,
    webhooks: bool,
}

impl Settings {
    pub(super) fn configured() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            key: env::var("MASTER_KEY")
                .ok()
                .map(|s| KeyEncryptionKey::new(&s))
                .transpose()?,
            quota: LoginThrottle::new(
                env::var("RATELIMIT_REGISTER_PER_MIN").map_or(Ok(10), |s| s.parse())?,
            ),
            hooks: env::var_os("HOOKS_ENABLED").is_none() || config::flag("HOOKS_ENABLED")?,
            webhooks: env::var_os("WEBHOOKS_ENABLED").is_none()
                || config::flag("WEBHOOKS_ENABLED")?,
        })
    }
}

fn fields(body: Value) -> Result<(String, String), Vec<Value>> {
    if !body.is_object() {
        return Err(vec![
            crate::request_json::token_field(body, "email", 0, usize::MAX).unwrap_err(),
        ]);
    }
    let email = crate::login_http::email_field(&body);
    let password = password_change::password_field(body, "password");
    match (email, password) {
        (Ok(email), Ok(password)) => Ok((email.to_lowercase(), password)),
        (email, password) => Err(email
            .err()
            .unwrap_or_default()
            .into_iter()
            .chain(password.err())
            .collect()),
    }
}

pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (headers, body) = match password_change::read_body(req).await {
        Ok(parts) => parts,
        Err(r) => return *r,
    };
    let (email, password) = match fields(body) {
        Ok(fields) => fields,
        Err(issues) => return password_change::invalid(issues),
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    register(
        &state,
        email,
        password,
        origin,
        value(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn refusal(
    pool: &PgPool,
    email: String,
    reason: &'static str,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Response {
    let subject = AuditSubject {
        user: None,
        email: Some(email),
        organization: None,
    };
    if write_activity(
        pool,
        AuditActivity::Registration(Some(reason)),
        subject,
        origin,
        request,
        Utc::now(),
    )
    .await
    .is_err()
    {
        eprintln!("could not record registration refusal");
    }
    if reason == "rate_limited" {
        RateLimited.into_response()
    } else {
        problem(StatusCode::CONFLICT, "Email already registered")
    }
}

async fn register(
    state: &Profile,
    email: String,
    password: String,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, Box<dyn Error + Send + Sync>> {
    let settings = &state.registration;
    if !settings.quota.allow(origin.ip) {
        return Ok(refusal(&state.pool, email, "rate_limited", origin, request).await);
    }
    if email_exists(&state.pool, &email).await? {
        return Ok(refusal(&state.pool, email, "already_registered", origin, request).await);
    }
    let Some(key) = &settings.key else {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Wallet encryption key unavailable",
        ));
    };
    let wallet = ManagedWallet::generate(key)?;
    let hash = state.scheme.hash(password).await?;
    let mut tx = state.pool.begin().await?;
    if settings.hooks && needs_dispatcher(&mut tx).await? {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Registration hook dispatcher unavailable",
        ));
    }
    let user = Uuid::new_v4();
    if !insert_user(&mut tx, user, &email, &hash, &wallet, false).await? {
        tx.rollback().await?;
        return Ok(refusal(&state.pool, email, "already_registered", origin, request).await);
    }
    let now = Utc::now();
    if settings.webhooks {
        enqueue_webhooks(&mut tx, user, now).await?;
    }
    let subject = AuditSubject {
        user: Some(user),
        email: Some(email.clone()),
        organization: None,
    };
    write_activity(
        &mut *tx,
        AuditActivity::Registration(None),
        subject,
        origin,
        request,
        now,
    )
    .await?;
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes)?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    sqlx::query("INSERT INTO email_verification_tokens(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)")
        .bind(Uuid::new_v4()).bind(user).bind(digest(&token)).bind(now+chrono::TimeDelta::hours(24)).execute(&mut *tx).await?;
    state.account_mail.send_verification(&email, &token).await?;
    tx.commit().await?;
    Ok(created_response(user, &email, &wallet))
}

async fn email_exists<'a>(db: impl sqlx::PgExecutor<'a>, email: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM users WHERE lower(primary_email)=$1)")
        .bind(email)
        .fetch_one(db)
        .await
}

fn created_response(id: Uuid, email: &str, wallet: &ManagedWallet) -> Response {
    let doc =
        json!({"user_id":id,"email":email,"public_key":wallet.public_key,"address":wallet.address});
    (StatusCode::CREATED, Json(doc)).into_response()
}

async fn insert_user(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    email: &str,
    hash: &str,
    wallet: &ManagedWallet,
    verified: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO users(id,primary_email,password_hash,public_key,encrypted_private_key,default_wallet_address,is_email_verified)
         VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(primary_email) DO NOTHING",
    )
    .bind(id)
    .bind(email)
    .bind(hash)
    .bind(&wallet.public_key)
    .bind(&wallet.encrypted_private_key)
    .bind(&wallet.address)
    .bind(verified)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn needs_dispatcher(tx: &mut Transaction<'_, Postgres>) -> Result<bool, sqlx::Error> {
    sqlx::query("LOCK TABLE hooks IN SHARE MODE")
        .execute(&mut **tx)
        .await?;
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM hooks WHERE is_active AND event_type='user_registered')",
    )
    .fetch_one(&mut **tx)
    .await
}

pub(crate) async fn enqueue_webhooks(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let event = Uuid::new_v4();
    let body=json!({"type":"user.registered","timestamp":now.to_rfc3339_opts(SecondsFormat::Secs,true),"data":{"user_id":user}}).to_string();
    sqlx::query("WITH subscriptions AS (
        SELECT id FROM webhook_subscriptions WHERE is_active AND event_types::jsonb ? 'user.registered'
    ), event AS (
        INSERT INTO webhook_events(id,type,body,occurred_at)
        SELECT $1,'user.registered',$2,$3 WHERE EXISTS(SELECT FROM subscriptions) RETURNING id
    ) INSERT INTO webhook_deliveries(id,event_id,subscription_id,next_attempt_at)
        SELECT gen_random_uuid(),event.id,subscriptions.id,$3 FROM event CROSS JOIN subscriptions")
        .bind(event).bind(body).bind(now).execute(&mut **tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn provisioning_preserves_the_original_accounts_verification_state() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE users(id uuid, primary_email text UNIQUE,
            password_hash text,public_key text,encrypted_private_key bytea,default_wallet_address text,is_email_verified boolean)")
            .execute(&mut *tx).await.unwrap();
        let wallet = ManagedWallet {
            public_key: "public".into(),
            address: "wallet".into(),
            encrypted_private_key: vec![1, 2],
        };
        for (email, verified) in [("self@example.test", false), ("admin@example.test", true)] {
            let user = Uuid::new_v4();
            assert!(
                insert_user(&mut tx, user, email, "original", &wallet, verified)
                    .await
                    .unwrap()
            );
            assert!(
                !insert_user(
                    &mut tx,
                    Uuid::new_v4(),
                    email,
                    "replacement",
                    &wallet,
                    !verified
                )
                .await
                .unwrap()
            );
            let stored: (Uuid, bool, String) = sqlx::query_as(
                "SELECT id,is_email_verified,password_hash FROM users WHERE primary_email=$1",
            )
            .bind(email)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(stored, (user, verified, "original".into()));
        }
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn only_matching_subscriptions_share_one_registration_event() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE webhook_subscriptions(id uuid,is_active boolean,event_types jsonb);
            CREATE TEMP TABLE webhook_events(id uuid,type text,body text,occurred_at timestamptz);
            CREATE TEMP TABLE webhook_deliveries(id uuid,event_id uuid,subscription_id uuid,next_attempt_at timestamptz)")
            .execute(&mut *tx).await.unwrap();
        let user = Uuid::new_v4();
        let now = Utc::now();
        enqueue_webhooks(&mut tx, user, now).await.unwrap();
        let initial: i64 = sqlx::query_scalar("SELECT count(*) FROM webhook_events")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(initial, 0);
        sqlx::raw_sql("INSERT INTO webhook_subscriptions VALUES
            (gen_random_uuid(),true,'[\"user.registered\"]'), (gen_random_uuid(),true,'[\"user.deleted\",\"user.registered\"]'),
            (gen_random_uuid(),false,'[\"user.registered\"]'), (gen_random_uuid(),true,'[\"user.deleted\"]')")
            .execute(&mut *tx).await.unwrap();
        enqueue_webhooks(&mut tx, user, now).await.unwrap();
        let rows=sqlx::query_as::<_,(Uuid,String,Uuid)>("SELECT event_id,body,subscription_id FROM webhook_deliveries d JOIN webhook_events e ON d.event_id=e.id")
            .fetch_all(&mut *tx).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, rows[1].0);
        assert_ne!(rows[0].2, rows[1].2);
        let body: Value = serde_json::from_str(&rows[0].1).unwrap();
        assert_eq!(
            body,
            json!({"type":"user.registered","timestamp":now.to_rfc3339_opts(SecondsFormat::Secs,true),"data":{"user_id":user}})
        );
    }
}
