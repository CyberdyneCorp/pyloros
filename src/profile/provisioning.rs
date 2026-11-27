//! Service-client account invitations.
mod input;
use super::*;
use crate::{
    authorization_codes::digest,
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::{problem, service_identity},
    login_throttle::{LoginThrottle, RateLimited},
    managed_wallet::ManagedWallet,
    token_http::{client_ip, header as value},
    token_revocation::VerifiedToken,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use input::Invitation;
use rand::{RngCore, rngs::OsRng};

pub(super) struct Settings {
    clients: LoginThrottle,
    addresses: LoginThrottle,
    invite_ttl: chrono::TimeDelta,
}
impl Settings {
    pub(super) fn configured() -> Result<Self, Box<dyn Error>> {
        let days = env::var("PROVISION_INVITE_TTL_DAYS").map_or(Ok(7), |s| s.parse())?;
        if !(1..=30).contains(&days) {
            return Err("PROVISION_INVITE_TTL_DAYS must be between 1 and 30".into());
        }
        Ok(Self {
            invite_ttl: chrono::TimeDelta::days(days),
            clients: LoginThrottle::new(
                env::var("RATELIMIT_PROVISION_PER_MIN").map_or(Ok(30), |s| s.parse())?,
            ),
            addresses: LoginThrottle::with_window(1, std::time::Duration::from_secs(86400)),
        })
    }
}
async fn authorize(state: &Profile, headers: &HeaderMap) -> Result<String, Box<Response>> {
    let raw = crate::csrf::bearer(headers)
        .ok_or_else(|| service_identity::unauthorized("Service token required"))?;
    let claims = state
        .verify
        .as_ref()
        .and_then(|v| {
            let mut validation = v.validation.clone();
            validation.set_required_spec_claims(&["iss", "exp"]);
            decode::<Value>(raw, &v.key, &validation).ok()
        })
        .ok_or_else(|| service_identity::unauthorized("Invalid token"))?
        .claims;
    let (client, id) = match VerifiedToken::from_verified_claims(&claims) {
        Ok(VerifiedToken::Service { client, id, .. }) => (client, id),
        Ok(VerifiedToken::Access { .. }) => {
            return Err(Box::new(problem(
                StatusCode::FORBIDDEN,
                "A service token is required",
            )));
        }
        _ => return Err(service_identity::unauthorized("Invalid token")),
    };
    let registration = service_identity::registration(&state.pool, &client, id, state.enforce)
        .await
        .map_err(|_| Box::new(internal()))?
        .map_err(service_identity::unauthorized)?;
    let scope = "users:provision";
    let granted = claims["scope"].as_str().unwrap_or_default();
    if ![granted, &registration.allowed_scopes]
        .iter()
        .all(|s| s.split_whitespace().any(|item| item == scope))
    {
        return Err(Box::new(problem(
            StatusCode::FORBIDDEN,
            "Insufficient scope: users:provision required",
        )));
    }
    Ok(client)
}
pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match admin_fields::body(&headers, &bytes) {
        Ok(body) => body,
        Err(r) => return *r,
    };
    let client = match authorize(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let Some(body) = body else { return internal() };
    let invitation = match input::parse(body) {
        Ok(i) => i,
        Err(issues) => return password_change::invalid(issues),
    };
    if !state.provisioning.clients.allow_client(Some(&client), None) {
        return RateLimited.into_response();
    }
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    provision(
        state,
        &client,
        invitation,
        origin,
        value(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}
fn accepted() -> Response {
    (StatusCode::ACCEPTED, Json(json!({"status":"accepted"}))).into_response()
}

async fn provision(
    state: Arc<Profile>,
    client: &str,
    invitation: Invitation,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, Box<dyn Error + Send + Sync>> {
    let Some(key) = &state.registration.key else {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Wallet encryption key unavailable",
        ));
    };
    let wallet = ManagedWallet::generate(key)?;
    let mut tx = state.pool.begin().await?;
    if state.registration.hooks && registration::pending_hook(&mut tx, "user_registered").await? {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Registration hook dispatcher unavailable",
        ));
    }
    let address = &invitation.email;
    if !state
        .provisioning
        .addresses
        .allow_client(Some(&digest(address)), None)
    {
        audit(&mut tx, client, "throttled", None).await?;
        tx.commit().await?;
        return Ok(accepted());
    }
    let existing = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT (SELECT id FROM users WHERE lower(primary_email)=$1)",
    )
    .bind(address)
    .fetch_one(&mut *tx)
    .await?;
    let (user, ttl, outcome) = match existing {
        Some(id) => (id, chrono::TimeDelta::hours(1), "existing"),
        None => {
            let Some(id) = insert(&mut tx, client, &invitation, &wallet).await? else {
                return Ok(accepted());
            };
            (id, state.provisioning.invite_ttl, "created")
        }
    };
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes)?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)",
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .bind(digest(&token))
    .bind(now + ttl)
    .execute(&mut *tx)
    .await?;
    audit(&mut tx, client, outcome, Some(user)).await?;
    if existing.is_none() {
        let subject = AuditSubject {
            user: Some(user),
            email: Some(address.clone()),
            organization: None,
        };
        write_activity(
            &mut *tx,
            AuditActivity::ServiceUserCreated(client),
            subject,
            origin,
            request,
            now,
        )
        .await?;
        if state.registration.webhooks {
            registration::enqueue_webhooks(&mut tx, user, now).await?;
        }
    }
    tx.commit().await?;
    tokio::spawn(async move {
        if state
            .account_mail
            .send_invitation(&invitation.email, &token, existing.is_none())
            .await
            .is_err()
        {
            eprintln!("account invitation email delivery failed");
        }
    });
    Ok(accepted())
}
async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
    invitation: &Invitation,
    wallet: &ManagedWallet,
) -> Result<Option<Uuid>, sqlx::Error> {
    let mut meta = json!({"created_via":format!("client:{client}")});
    if let Some(name) = &invitation.name {
        meta["provisioned_name"] = json!(name);
    }
    if let Some(locale) = &invitation.locale {
        meta["locale"] = json!(locale);
    }
    sqlx::query_scalar("INSERT INTO users(id,primary_email,public_key,encrypted_private_key,default_wallet_address,is_email_verified,extra_metadata)
        VALUES($1,$2,$3,$4,$5,false,$6) ON CONFLICT(primary_email) DO NOTHING RETURNING id")
        .bind(Uuid::new_v4()).bind(&invitation.email).bind(&wallet.public_key)
        .bind(&wallet.encrypted_private_key).bind(&wallet.address).bind(meta)
        .fetch_optional(&mut **tx).await
}
async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
    outcome: &str,
    user: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    let id = user.map(|u| u.to_string());
    crate::admin_audit::append_record(
        tx,
        "user.provision",
        None,
        id.as_deref().map(|s| ("user", s)),
        json!({"client_id":client,"outcome":outcome}),
        SessionOrigin {
            ip: None,
            user_agent: None,
        },
    )
    .await
}
