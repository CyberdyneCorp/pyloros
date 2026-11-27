//! Redeem an emailed recovery credential against shared PostgreSQL state.
use super::email_verification::{Refusal, TokenRow, owner, verify_account};
use super::*;
use crate::{
    authorization_codes::digest,
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    request_json::fields::read_fields,
    token_http::{client_ip, header as value},
};

pub(super) async fn confirm(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return crate::token_http::post_only().await;
    }
    let (parts, stream) = req.into_parts();
    let headers = parts.headers;
    let fields = read_fields(&headers, stream, &["token", "new_password"], |body| {
        password_change::fields(body, "token")
    })
    .await;
    let (token, password) = match fields {
        Ok(fields) => fields,
        Err(response) => return *response,
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    redeem(
        &state,
        &digest(&token),
        password,
        origin,
        value(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn refuse(
    pool: &PgPool,
    (reason, user): Refusal,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Response {
    let subject = AuditSubject {
        user,
        email: None,
        organization: None,
    };
    if write_activity(
        pool,
        AuditActivity::PasswordReset(Err(reason)),
        subject,
        origin,
        request,
        Utc::now(),
    )
    .await
    .is_err()
    {
        eprintln!("could not record password reset refusal");
    }
    problem(StatusCode::BAD_REQUEST, "Invalid or expired reset token")
}

async fn redeem(
    state: &Profile,
    token_hash: &str,
    password: String,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, Box<dyn Error + Send + Sync>> {
    const LOOKUP: &str = "SELECT user_id,expires_at,used_at FROM password_reset_tokens WHERE id=(SELECT id FROM password_reset_tokens WHERE token_hash=$1)";
    let row = sqlx::query_as::<_, TokenRow>(LOOKUP)
        .bind(token_hash)
        .fetch_optional(&state.pool)
        .await?;
    if let Err(reason) = owner(row) {
        return Ok(refuse(&state.pool, reason, origin, request).await);
    }
    let hash = state.scheme.hash(password).await?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query_as::<_, TokenRow>(&format!("{LOOKUP} FOR UPDATE"))
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await?;
    let id = match owner(row) {
        Ok(user) => user,
        Err(reason) => {
            tx.rollback().await?;
            return Ok(refuse(&state.pool, reason, origin, request).await);
        }
    };
    let now = Utc::now();
    let Some(subject) = verify_account(&mut tx, id).await? else {
        tx.rollback().await?;
        return Ok(refuse(&state.pool, ("user_not_found", Some(id)), origin, request).await);
    };
    sqlx::query("UPDATE users SET password_hash=$2,tokens_valid_after=GREATEST(tokens_valid_after,$3) WHERE id=$1")
        .bind(id).bind(hash).bind(now).execute(&mut *tx).await?;
    sqlx::query("UPDATE password_reset_tokens SET used_at=$2 WHERE token_hash=$1")
        .bind(token_hash)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    let count = logout_all::revoke_sessions(&mut tx, id, now).await?;
    write_activity(
        &mut *tx,
        AuditActivity::PasswordReset(Ok(count)),
        subject,
        origin,
        request,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(super) async fn request(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return crate::token_http::post_only().await;
    }
    let (parts, stream) = req.into_parts();
    let headers = parts.headers;
    let email = match read_fields(&headers, stream, &["email"], recovery_email).await {
        Ok(email) => email,
        Err(response) => return *response,
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    if !state.reset_quota.allow(origin.ip) {
        let mut response = problem(StatusCode::TOO_MANY_REQUESTS, "Too many requests");
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, "3600".parse().unwrap());
        return response;
    }
    issue(&state, email, origin, value(&headers, "x-request-id"))
        .await
        .unwrap_or_else(|_| internal())
}

fn recovery_email(body: Value) -> Result<String, Vec<Value>> {
    if body.is_object() {
        return crate::login_http::email_field(&body);
    }
    crate::request_json::token_field(body, "email", 0, usize::MAX).map_err(|issue| vec![issue])
}

async fn issue(
    state: &Profile,
    email: String,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, Box<dyn Error + Send + Sync>> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::{RngCore, rngs::OsRng};
    let mut tx = state.pool.begin().await?;
    let account = sqlx::query_as::<_, (Uuid, String, Option<Uuid>)>(
        "SELECT id,primary_email,organization_id FROM users WHERE id=(SELECT id FROM users WHERE lower(primary_email)=lower($1))",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await?;
    let now = Utc::now();
    let Some((id, recipient, organization)) = account else {
        tx.rollback().await?;
        let subject = AuditSubject {
            user: None,
            email: Some(email),
            organization: None,
        };
        if write_activity(
            &state.pool,
            AuditActivity::ResetRequested(Some("user_not_found")),
            subject,
            origin,
            request,
            now,
        )
        .await
        .is_err()
        {
            eprintln!("could not record password reset request refusal");
        }
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes)?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    sqlx::query(
        "INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)",
    )
    .bind(Uuid::new_v4())
    .bind(id)
    .bind(digest(&token))
    .bind(now + chrono::TimeDelta::hours(1))
    .execute(&mut *tx)
    .await?;
    state.account_mail.send_reset(&recipient, &token).await?;
    let subject = AuditSubject {
        user: Some(id),
        email: Some(recipient),
        organization,
    };
    write_activity(
        &mut *tx,
        AuditActivity::ResetRequested(None),
        subject,
        origin,
        request,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn confirmation_reports_both_errors_with_original_inputs() {
        use axum::body::{Body, to_bytes};
        use tower::ServiceExt;

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/pyloros")
            .unwrap();
        let request = Request::post("/api/v1/auth/password/reset-confirm")
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))))
            .body(Body::from(
                r#"{"token":[184467440737095516171],"unrelated":42}"#,
            ))
            .unwrap();
        let response = routes(pool, false).unwrap().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = to_bytes(response.into_body(), 2048).await.unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        assert!(body.contains(r#""input":[184467440737095516171]"#));
        assert!(body.contains(r#""input":{"token":[184467440737095516171],"unrelated":42}"#));
        assert!(
            body.find(r#"["body","token"]"#).unwrap()
                < body.find(r#"["body","new_password"]"#).unwrap()
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn reset_token_can_be_redeemed_once_and_membership_follows_verified_email() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid,primary_email text,organization_id uuid,is_email_verified boolean,password_hash text,tokens_valid_after timestamptz);
            CREATE TEMP TABLE password_reset_tokens(id uuid,user_id uuid,token_hash text,expires_at timestamptz,used_at timestamptz);
            CREATE TEMP TABLE organizations(id uuid,domain_name text,is_active boolean);
            CREATE TEMP TABLE user_organizations(user_id uuid,organization_id uuid,primary key(user_id,organization_id));
            CREATE TEMP TABLE sessions(user_id uuid,revoked_at timestamptz);
            CREATE TEMP TABLE auth_events(activity text,outcome text,reason_code text,details jsonb)").execute(&pool).await.unwrap();
        let (id, org) = (Uuid::new_v4(), Uuid::new_v4());
        sqlx::query("INSERT INTO users VALUES($1,'member@example.org',NULL,false,NULL,NULL)")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO organizations VALUES($1,'Example.Org',true)")
            .bind(org)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions VALUES($1,NULL)")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let state = Profile {
            blockchain: Default::default(),
            builtin_scopes: Default::default(),
            configured_resources: Default::default(),
            configured_origins: Default::default(),
            client_scopes: Default::default(),
            admin_enabled: true,
            passkeys: passkeys::Inventory::new(None, 10),
            oidc_enabled: false,
            provisioning: provisioning::Settings::configured().unwrap(),
            wallet_challenges: wallet_challenge::issue::Settings::configured().unwrap(),
            registration: registration::Settings::configured().unwrap(),
            erasure: erasure::Settings::configured().unwrap(),
            account_mail: crate::email_delivery::ConfirmationMailer::mock(),
            reset_quota: crate::login_throttle::LoginThrottle::new(0),
            scheme: crate::passwords::PasswordScheme::Bcrypt,
            pool: pool.clone(),
            verify: None,
            enforce: false,
            admins: vec![],
            production: false,
            proxies: 0,
            factor: None,
            mfa_issuer: String::new(),
            cookies: crate::session_cookies::SessionCookies::configured(false).unwrap(),
        };
        let origin = SessionOrigin {
            ip: None,
            user_agent: None,
        };
        assert_eq!(
            issue(&state, "MEMBER@example.org".into(), origin, None)
                .await
                .unwrap()
                .status(),
            204
        );
        let messages = state.account_mail.take_mock_resets().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].0, "member@example.org");
        let token = digest(&messages[0].1);
        assert_eq!(
            redeem(&state, &token, "Fresh-Password1".into(), origin, None)
                .await
                .unwrap()
                .status(),
            204
        );
        assert_eq!(
            redeem(&state, &token, "Wrong-Password2".into(), origin, None)
                .await
                .unwrap()
                .status(),
            400
        );
        let (hash,member,verified,revoked,consumed): (String,Uuid,bool,bool,bool)=sqlx::query_as("SELECT u.password_hash,m.organization_id,u.is_email_verified,s.revoked_at IS NOT NULL,t.used_at IS NOT NULL
            FROM users u JOIN user_organizations m ON m.user_id=u.id AND m.organization_id=u.organization_id
            JOIN sessions s ON s.user_id=u.id JOIN password_reset_tokens t ON t.user_id=u.id")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(member, org);
        assert!(
            verified && revoked && consumed && bcrypt::verify("Fresh-Password1", &hash).unwrap()
        );
    }
}
