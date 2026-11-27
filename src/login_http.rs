//! Password login for the PostgreSQL identity backend.
mod cli;
mod config;
pub(crate) use config::identity as signing_identity;
mod email_domain;
mod mailbox;
pub(crate) use mailbox::recipient as account_recipient;
mod end_session;
mod federated;
mod input;
mod introspect;
pub(crate) mod service_identity;
pub(crate) use input::email_field;
mod logout;
mod mfa;
use crate::enrolled_factor::FactorVerifier;
mod passkey;
mod poll;
mod refresh;
mod revoke;
use crate::mfa_challenges::ChallengeVerifier;
use crate::{
    email_challenge::{self, ConfirmationDecision, ConfirmationError, ConfirmationPolicy},
    email_delivery::ConfirmationMailer,
    first_party::{AuthenticatedLogin, LoginPolicy},
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    grant_sessions::GrantSessionIssuer,
    login_throttle::LoginThrottle,
    password_login::{self, PasswordAttempt, PasswordDecision},
    passwords::PasswordScheme,
    session_cookies::SessionCookies,
    signing::SigningIdentity,
    token_http::{client_ip, header},
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    http::{StatusCode, header as h},
    response::{IntoResponse, Response},
    routing::any,
};
use chrono::{TimeDelta, Utc};
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use std::{env, error::Error, net::SocketAddr, sync::Arc};
use uuid::Uuid;

pub(crate) struct Login {
    signed_out: String,
    passkeys: Option<passkey::Policy>,
    pool: PgPool,
    signing: SigningIdentity,
    issuer: GrantSessionIssuer,
    mail: ConfirmationMailer,
    cookies: SessionCookies,
    access: TimeDelta,
    refresh: TimeDelta,
    reuse_grace: TimeDelta,
    challenge: TimeDelta,
    scheme: PasswordScheme,
    admins: Vec<String>,
    production: bool,
    hooks: bool,
    proxies: usize,
    cli_quota: LoginThrottle,
    revoke_quota: LoginThrottle,
    enforce_revocation: bool,
    throttle: LoginThrottle,
    poll_quota: LoginThrottle,
    mfa_quota: LoginThrottle,
    factor: Option<FactorVerifier>,
    verifier: ChallengeVerifier,
}

pub fn routes(pool: PgPool, production: bool) -> Result<Router, Box<dyn Error>> {
    let login = Login::configured(pool, production)?.map(Arc::new);
    with_state(login)
}

pub async fn routes_with_external(
    pool: PgPool,
    environment: &str,
    interval: std::time::Duration,
) -> Result<Router, Box<dyn Error>> {
    let login = Login::configured(pool.clone(), environment == "production")?.map(Arc::new);
    let router = with_state(login.clone())?;
    Ok(router.merge(crate::external_oauth::with_login(pool, environment, interval, login).await?))
}

pub(crate) fn routes_with_redirects(
    pool: PgPool,
    environment: &str,
    allowed: crate::browser_policy::OriginCatalog,
) -> Result<Router, Box<dyn Error>> {
    let login = Login::configured(pool.clone(), environment == "production")?.map(Arc::new);
    Ok(
        with_state(login.clone())?.merge(crate::external_oauth::with_redirects(
            pool,
            environment,
            login,
            allowed,
        )?),
    )
}

fn with_state(login: Option<Arc<Login>>) -> Result<Router, Box<dyn Error>> {
    let end_session = if crate::config::flag("OIDC_ENABLED")? {
        any(end_session::handle)
    } else {
        any(end_session::disabled)
    };
    Ok(Router::new()
        .route("/api/v1/auth/oauth2/logout", end_session)
        .route("/api/v1/auth/oauth2/revoke", any(revoke::handle))
        .route("/api/v1/auth/introspect", any(introspect::handle))
        .route("/api/v1/clients/me", any(service_identity::handle))
        .route("/api/v1/auth/passkeys/login/verify", any(passkey::handle))
        .route(
            "/api/v1/auth/cli/exchange",
            any(cli::handle).layer(axum::Extension(crate::config::flag("CLI_LOGIN_ENABLED")?)),
        )
        .route("/api/v1/auth/login", any(handle))
        .route("/api/v1/auth/refresh", any(refresh::handle))
        .route("/api/v1/auth/logout", any(logout::handle))
        .route("/api/v1/auth/mfa/verify", any(mfa::handle))
        .route("/api/v1/auth/magic-link/status", any(poll::handle))
        .with_state(login))
}

pub(crate) fn problem(status: StatusCode, title: &str) -> Response {
    (
        status,
        Json(json!({"type":"about:blank","title":title,"status":status.as_u16(),"detail":title})),
    )
        .into_response()
}

pub(crate) fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
    )
        .into_response()
}

async fn handle(
    State(state): State<Option<Arc<Login>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() != axum::http::Method::POST {
        let mut res = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        res.headers_mut().insert(h::ALLOW, "POST".parse().unwrap());
        return res;
    }
    let Some(login) = state else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Login signing unavailable");
    };
    let (parts, body) = req.into_parts();
    let (email, password) = match input::read(&parts.headers, body, input::credentials).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let origin = SessionOrigin {
        ip: client_ip(&parts.headers, peer.ip(), login.proxies),
        user_agent: header(&parts.headers, "user-agent"),
    };
    let id = header(&parts.headers, "x-request-id");
    login
        .run(PasswordAttempt {
            email: &email,
            password,
            origin,
            request_id: id,
        })
        .await
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
            )
                .into_response()
        })
}

fn challenge(method: &str, token: String, code: Option<String>) -> Response {
    Json(json!({"mfa_required":true,"mfa_token":token,"mfa_method":method,"match_code":code}))
        .into_response()
}

#[derive(Clone, Copy)]
enum Primary {
    Password,
    Passkey,
}
impl Primary {
    fn audit(self) -> &'static str {
        match self {
            Self::Password => "pwd",
            Self::Passkey => "user",
        }
    }
}

enum LoginMethod {
    Passkey(Uuid),
    Password,
    Email(chrono::DateTime<Utc>),
    Totp(Primary),
    Recovery(Primary),
}

type LoginResult = Result<Response, Box<dyn Error + Send + Sync>>;

impl Login {
    async fn run(&self, attempt: PasswordAttempt<'_>) -> LoginResult {
        if let Err(limit) = self.throttle.admit(&self.pool, &attempt).await {
            return Ok(limit.into_response());
        }
        let origin = attempt.origin;
        let request_id = attempt.request_id;
        let (user, tx) = match password_login::evaluate(
            &self.pool,
            self.scheme,
            &self.signing,
            self.challenge,
            attempt,
        )
        .await?
        {
            PasswordDecision::InvalidCredentials => {
                return Ok(problem(StatusCode::UNAUTHORIZED, "Invalid credentials"));
            }
            PasswordDecision::Inactive => {
                return Ok(problem(StatusCode::FORBIDDEN, "User is inactive"));
            }
            PasswordDecision::Totp { token } => return Ok(challenge("totp", token, None)),
            PasswordDecision::Continue { user, transaction } => (user, transaction),
        };
        let policy = ConfirmationPolicy {
            signer: &self.signing,
            lifetime: self.challenge,
            origin,
            request_id,
        };
        match email_challenge::require_if_due(&self.pool, tx, user, policy, |m| self.mail.send(m))
            .await
        {
            Ok(ConfirmationDecision::Continue(tx)) => {
                self.finish(tx, user, origin, request_id, LoginMethod::Password)
                    .await
            }
            Ok(ConfirmationDecision::Pending {
                mfa_token,
                match_code,
            }) => Ok(challenge("magic_link", mfa_token, Some(match_code))),
            Err(ConfirmationError::Delivery) => Ok(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Could not send the confirmation email",
            )),
            Err(e) => Err(e.into()),
        }
    }
    async fn finish(
        &self,
        mut tx: Transaction<'_, Postgres>,
        user: Uuid,
        origin: SessionOrigin<'_>,
        request_id: Option<&str>,
        method: LoginMethod,
    ) -> LoginResult {
        if self.hooks {
            // Keep hook activation ordered with the session commit during coexistence.
            sqlx::query("LOCK TABLE hooks IN SHARE MODE")
                .execute(&mut *tx)
                .await?;
            let subscribed = sqlx::query_scalar::<_,bool>(
                "SELECT EXISTS(SELECT 1 FROM hooks WHERE is_active AND event_type='user_logged_in')"
            ).fetch_one(&mut *tx).await?;
            if subscribed {
                return Ok(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Login hook dispatcher unavailable",
                ));
            }
        }
        let now = Utc::now();
        let account = AuthenticatedLogin {
            user,
            authenticated_at: match method {
                LoginMethod::Email(at) => at,
                _ => now,
            },
            methods: match method {
                LoginMethod::Passkey(_) => &["mfa", "swk", "user"],
                LoginMethod::Password => &["pwd"],
                LoginMethod::Email(_) => &["pwd", "mca"],
                LoginMethod::Totp(Primary::Password) => &["pwd", "otp", "mfa"],
                LoginMethod::Totp(Primary::Passkey) => &["swk", "user", "otp", "mfa"],
                LoginMethod::Recovery(Primary::Password) => &["pwd", "mfa"],
                LoginMethod::Recovery(Primary::Passkey) => &["swk", "user", "mfa"],
            },
            origin,
        };
        let policy = LoginPolicy {
            access_lifetime: self.access,
            admin_emails: &self.admins,
            require_verified_admin_email: self.production,
        };
        let pair = self
            .issuer
            .issue_first_party(&mut tx, account, &policy, now)
            .await?;
        let (email, organization) = sqlx::query_as::<_, (Option<String>, Option<Uuid>)>(
            "SELECT primary_email,organization_id FROM users WHERE id=$1",
        )
        .bind(user)
        .fetch_one(&mut *tx)
        .await?;
        write_activity(
            &mut *tx,
            match method {
                LoginMethod::Passkey(key) => AuditActivity::PasskeyLogin(pair.session, key),
                LoginMethod::Password => AuditActivity::PasswordLogin(pair.session),
                LoginMethod::Email(_) => AuditActivity::EmailLogin(pair.session),
                LoginMethod::Totp(primary) => {
                    AuditActivity::FactorLogin(pair.session, "totp", primary.audit())
                }
                LoginMethod::Recovery(primary) => {
                    AuditActivity::FactorLogin(pair.session, "recovery_code", primary.audit())
                }
            },
            AuditSubject {
                user: Some(user),
                email,
                organization,
            },
            origin,
            request_id,
            now,
        )
        .await?;
        let res = self.token_response(&pair.access_token, &pair.refresh_token)?;
        tx.commit().await?;
        Ok(res)
    }

    fn token_response(&self, access: &str, refresh: &str) -> LoginResult {
        let mut res =
            Json(json!({"access_token":access,"refresh_token":refresh,"token_type":"Bearer"}))
                .into_response();
        self.cookies.set(
            res.headers_mut(),
            access,
            refresh,
            self.access.num_seconds() as u64,
            self.refresh.num_seconds() as u64,
        )?;
        Ok(res)
    }
}
