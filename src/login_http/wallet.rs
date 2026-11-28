//! Authenticate an external wallet against a stored, single-use challenge.
mod input;
mod signature;
use super::*;
use axum::{body::Bytes, http::HeaderMap};
use chrono::DateTime;
use uuid::Uuid;

pub(super) async fn handle(
    State(login): State<Option<Arc<Login>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let raw = match crate::request_json::iam_document::document(&headers, &bytes) {
        Ok(Some(raw)) => raw,
        Ok(None) => return internal_error(),
        Err(r) => return *r,
    };
    let Some(login) = login else {
        return internal_error();
    };
    if let Some(provider) = login.issuer.blockchain.provider().await
        && provider.validate_signer().is_err()
    {
        return internal_error();
    }
    let (id, sig) = match input::parse(&raw) {
        Ok(pair) => pair,
        Err(r) => return *r,
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), login.proxies),
        user_agent: header(&headers, "user-agent"),
    };
    if !login.wallet_quota.allow(origin.ip) {
        return crate::login_throttle::RateLimited.into_response();
    }
    let attempt = Attempt {
        login: &login,
        origin,
        request_id: header(&headers, "x-request-id"),
    };
    attempt
        .verify(id, &sig)
        .await
        .unwrap_or_else(|_| internal_error())
}

struct Attempt<'a> {
    login: &'a Login,
    origin: SessionOrigin<'a>,
    request_id: Option<&'a str>,
}

struct Account {
    user: Uuid,
    org: Option<Uuid>,
    active: bool,
    new: bool,
}

impl Attempt<'_> {
    async fn verify(&self, id: Uuid, sig: &str) -> LoginResult {
        let mut tx = self.login.pool.begin().await?;
        let row = sqlx::query_as::<_, (String, i32, String, Option<DateTime<Utc>>, String)>(
            "SELECT wallet_address,chain_id,status,expires_at,COALESCE(extra_metadata::text,'null')
             FROM auth_challenges WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((address, chain_id, status, expires_at, stored_metadata)) = row else {
            return self.refuse(tx, None, None, "invalid_state").await;
        };
        let normalized = metadata(&stored_metadata)?;
        let did = format!("did:pkh:eip155:{}:{}", chain_id, address.to_lowercase());
        let now = Utc::now();
        match status.as_str() {
            "pending" if expires_at.is_some_and(|t| t >= now) => {}
            "pending" => return self.refuse(tx, Some(&did), None, "expired").await,
            "consumed" | "expired" | "failed" | "completed" => {
                return self.refuse(tx, Some(&did), None, "replay_detected").await;
            }
            _ => return Ok(internal_error()),
        }
        if !claim(&mut tx, id).await? {
            return self.refuse(tx, Some(&did), None, "replay_detected").await;
        }
        let msg = message(normalized.as_deref().unwrap_or(&stored_metadata))?;
        if !signature::signer(&msg, sig).is_some_and(|s| s.eq_ignore_ascii_case(&address)) {
            // The failed attempt is visible to constraints before its transaction rolls back.
            sqlx::query("UPDATE auth_challenges SET status='failed',completed_at=$2 WHERE id=$1")
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            return self.refuse(tx, Some(&did), None, "invalid_signature").await;
        }
        let account = account(&mut tx, &address, self.login.wallet_webhooks, now).await?;
        if !account.active {
            return self
                .refuse(tx, Some(&did), Some(&account), "inactive")
                .await;
        }
        self.complete(tx, id, &address, &did, account, now).await
    }

    async fn refuse(
        &self,
        tx: Transaction<'_, Postgres>,
        did: Option<&str>,
        account: Option<&Account>,
        reason: &'static str,
    ) -> LoginResult {
        tx.rollback().await?;
        if write_activity(
            &self.login.pool,
            AuditActivity::Wallet {
                did,
                reason: Some(reason),
                details: json!({}),
            },
            audit_subject(account),
            self.origin,
            self.request_id,
            Utc::now(),
        )
        .await
        .is_err()
        {
            eprintln!("could not record wallet login refusal");
        }
        let (status, title) = match reason {
            "invalid_state" => (StatusCode::NOT_FOUND, "Challenge not found"),
            "invalid_signature" => (StatusCode::UNAUTHORIZED, "Invalid signature"),
            "inactive" => (StatusCode::FORBIDDEN, "User is inactive"),
            _ => (StatusCode::BAD_REQUEST, "Challenge expired"),
        };
        Ok(problem(status, title))
    }

    async fn complete(
        &self,
        mut tx: Transaction<'_, Postgres>,
        id: Uuid,
        address: &str,
        did: &str,
        account: Account,
        now: DateTime<Utc>,
    ) -> LoginResult {
        let login = self.login;
        let pair = login
            .issuer
            .issue_first_party(
                &mut tx,
                AuthenticatedLogin {
                    user: account.user,
                    authenticated_at: now,
                    methods: &["pop"],
                    origin: SessionOrigin {
                        ip: None,
                        user_agent: None,
                    },
                },
                &LoginPolicy {
                    access_lifetime: login.access,
                    admin_emails: &login.admins,
                    require_verified_admin_email: login.production,
                },
                now,
            )
            .await?;
        sqlx::query(
            "UPDATE auth_challenges SET status='completed',user_id=$2,completed_at=$3 WHERE id=$1",
        )
        .bind(id)
        .bind(account.user)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        write_activity(
            &mut *tx,
            AuditActivity::Wallet {
                did: Some(did),
                reason: None,
                details: json!({"session_id":pair.session,"is_new_user":account.new}),
            },
            audit_subject(Some(&account)),
            self.origin,
            self.request_id,
            Utc::now(),
        )
        .await?;
        let mut response = Json(json!({
            "access_token": pair.access_token,
            "refresh_token": pair.refresh_token,
            "token_type": "Bearer",
            "wallet_address": address,
            "is_new_user": account.new,
        }))
        .into_response();
        login.cookies.set(
            response.headers_mut(),
            &pair.access_token,
            &pair.refresh_token,
            login.access.num_seconds() as u64,
            login.refresh.num_seconds() as u64,
        )?;
        tx.commit().await?;
        Ok(response)
    }
}

async fn claim(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE auth_challenges SET status='consumed' WHERE id=$1 AND status='pending'",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected() == 1)
}

fn audit_subject(account: Option<&Account>) -> AuditSubject {
    AuditSubject {
        user: account.map(|a| a.user),
        email: None,
        organization: account.and_then(|a| a.org),
    }
}

fn metadata(doc: &str) -> Result<Option<String>, sqlx::Error> {
    crate::profile::normalized_storage(doc)
}

fn message(doc: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    let values: std::collections::HashMap<String, &serde_json::value::RawValue> =
        serde_json::from_str(doc)?;
    match values.get("message") {
        None => Ok(String::new()),
        Some(raw) if raw.get().starts_with('"') => Ok(serde_json::from_str(raw.get())?),
        Some(raw) => Ok(crate::json_representation::representation(raw)?),
    }
}

async fn account(
    tx: &mut Transaction<'_, Postgres>,
    address: &str,
    webhooks: bool,
    now: DateTime<Utc>,
) -> Result<Account, sqlx::Error> {
    let matches = sqlx::query_as::<_, (Uuid, Option<Uuid>, bool, String)>(
        "SELECT id,organization_id,is_active,COALESCE(extra_metadata::text,'null')
         FROM users WHERE lower(default_wallet_address)=lower($1) LIMIT 2",
    )
    .bind(address)
    .fetch_all(&mut **tx)
    .await?;
    match matches.as_slice() {
        [(user, org, active, doc)] => {
            metadata(doc)?;
            return Ok(Account {
                user: *user,
                org: *org,
                active: *active,
                new: false,
            });
        }
        [] => {}
        _ => return Err(sqlx::Error::Protocol("ambiguous wallet account".into())),
    }
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,default_wallet_address) VALUES($1,$2)")
        .bind(user)
        .bind(address)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO user_identities(id,user_id,type,provider,identifier,extra_data)
         VALUES($1,$2,'wallet','evm',$3,'{}')",
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .bind(address)
    .execute(&mut **tx)
    .await?;
    if webhooks {
        crate::profile::enqueue_webhooks(tx, user, now).await?
    }
    Ok(Account {
        user,
        org: None,
        active: true,
        new: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn rollback_releases_a_claim_and_commit_consumes_it() -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE auth_challenges(id uuid PRIMARY KEY,status text)")
            .execute(&pool)
            .await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO auth_challenges VALUES($1,'pending')")
            .bind(id)
            .execute(&pool)
            .await?;
        let mut refused = pool.begin().await?;
        assert!(claim(&mut refused, id).await?);
        refused.rollback().await?;
        let mut valid = pool.begin().await?;
        assert!(claim(&mut valid, id).await?);
        valid.commit().await?;
        let mut duplicate = pool.begin().await?;
        assert!(!claim(&mut duplicate, id).await?);
        duplicate.rollback().await
    }
}
