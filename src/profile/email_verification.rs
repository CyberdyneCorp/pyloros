//! Verify a registered email using the delivered single-use token.
use super::*;
use crate::{
    authorization_codes::digest,
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    token_http::{client_ip, header as value},
};
pub(super) type TokenRow = (Uuid, DateTime<Utc>, Option<DateTime<Utc>>);
pub(super) type Refusal = (&'static str, Option<Uuid>);

pub(super) fn owner(row: Option<TokenRow>) -> Result<Uuid, Refusal> {
    match row {
        Some((id, expires, None)) if expires < Utc::now() => Err(("expired", Some(id))),
        Some((id, _, None)) => Ok(id),
        _ => Err(("invalid_token", None)),
    }
}

pub(crate) async fn verify_account(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<AuditSubject>, sqlx::Error> {
    let account = sqlx::query_as::<_, (Option<String>, Option<Uuid>)>(
        "SELECT primary_email,organization_id FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((email, organization)) = account else {
        return Ok(None);
    };
    let organization = match organization {
        Some(org) => Some(org),
        None => join_email_domain(tx, id, email.as_deref()).await?,
    };
    sqlx::query("UPDATE users SET is_email_verified=true,organization_id=$2 WHERE id=$1")
        .bind(id)
        .bind(organization)
        .execute(&mut **tx)
        .await?;
    Ok(Some(AuditSubject {
        user: Some(id),
        email,
        organization,
    }))
}

async fn join_email_domain(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    email: Option<&str>,
) -> Result<Option<Uuid>, sqlx::Error> {
    let Some((_, domain)) = email.and_then(|s| s.rsplit_once('@')) else {
        return Ok(None);
    };
    let org: Option<Uuid> = sqlx::query_scalar(
        "SELECT (SELECT id FROM organizations WHERE is_active AND lower(domain_name)=lower($1))",
    )
    .bind(domain)
    .fetch_one(&mut **tx)
    .await?;
    if let Some(id) = org {
        sqlx::query("INSERT INTO user_organizations(user_id,organization_id) VALUES($1,$2) ON CONFLICT(user_id,organization_id) DO NOTHING")
            .bind(user).bind(id).execute(&mut **tx).await?;
    }
    Ok(org)
}

pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (headers, body) = match password_change::read_body(req).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let token = match crate::request_json::token_field(body, "token", 0, usize::MAX) {
        Ok(token) => token,
        Err(issue) => return password_change::invalid(vec![issue]),
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    redeem(
        &state.pool,
        &digest(&token),
        origin,
        value(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn redeem(
    pool: &PgPool,
    hash: &str,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row=sqlx::query_as::<_,TokenRow>("SELECT user_id,expires_at,used_at FROM email_verification_tokens WHERE id=(SELECT id FROM email_verification_tokens WHERE token_hash=$1) FOR UPDATE")
        .bind(hash).fetch_optional(&mut *tx).await?;
    let decision = match owner(row) {
        Ok(id) => verify_account(&mut tx, id)
            .await?
            .ok_or(("user_not_found", Some(id))),
        Err(reason) => Err(reason),
    };
    let now = Utc::now();
    let subject = match decision {
        Ok(subject) => subject,
        Err((reason, user)) => {
            tx.rollback().await?;
            let subject = AuditSubject {
                user,
                email: None,
                organization: None,
            };
            if write_activity(
                pool,
                AuditActivity::EmailVerified(Some(reason)),
                subject,
                origin,
                request,
                now,
            )
            .await
            .is_err()
            {
                eprintln!("could not record email verification refusal");
            }
            return Ok(problem(
                StatusCode::BAD_REQUEST,
                "Invalid or expired verification token",
            ));
        }
    };
    sqlx::query("UPDATE email_verification_tokens SET used_at=$2 WHERE token_hash=$1")
        .bind(hash)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    write_activity(
        &mut *tx,
        AuditActivity::EmailVerified(None),
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
    #[ignore = "requires PostgreSQL"]
    async fn failed_audit_preserves_verification_token_and_account_state() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid,primary_email text,organization_id uuid,is_email_verified boolean);
            CREATE TEMP TABLE email_verification_tokens(id uuid,user_id uuid,token_hash text,expires_at timestamptz,used_at timestamptz);
            CREATE TEMP TABLE auth_events(activity text CHECK(activity <> 'email_verify'))").execute(&pool).await.unwrap();
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES($1,'member@example.org',$2,false)")
            .bind(user)
            .bind(Uuid::new_v4())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO email_verification_tokens VALUES($1,$2,'test-digest',now()+interval '1 hour',NULL)")
            .bind(Uuid::new_v4()).bind(user).execute(&pool).await.unwrap();
        let origin = SessionOrigin {
            ip: None,
            user_agent: None,
        };
        assert!(redeem(&pool, "test-digest", origin, None).await.is_err());
        let state:(bool,bool)=sqlx::query_as("SELECT is_email_verified,used_at IS NOT NULL FROM users JOIN email_verification_tokens ON user_id=users.id")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(state, (false, false));
        sqlx::query("ALTER TABLE auth_events DROP CONSTRAINT auth_events_activity_check")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            redeem(&pool, "test-digest", origin, None)
                .await
                .unwrap()
                .status(),
            204
        );
        assert_eq!(
            redeem(&pool, "test-digest", origin, None)
                .await
                .unwrap()
                .status(),
            400
        );
    }
}
