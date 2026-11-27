pub mod access_tokens;
pub mod authorization_codes;
pub mod browser_client;
mod browser_http;
mod browser_policy;
pub mod browser_prompt;
pub mod chain_settings;
mod client_auth;
pub mod code_decision;
pub mod code_exchange;
pub mod config;
mod consent_http;
mod consent_page;
pub mod cors;
mod csrf;
pub mod discovery;
pub mod email_challenge;
pub mod email_delivery;
pub mod email_link_http;
pub mod first_party;
mod foundation;
mod grant_audit;
pub mod grant_response;
pub mod grant_sessions;
pub mod headers;
pub mod id_tokens;
pub mod key_encryption;
pub mod login_http;
pub mod login_methods;
pub mod login_throttle;
pub mod managed_wallet;
pub mod mfa_challenges;
pub mod oauth_refresh;
mod oauth_uri;
pub mod passkey_assertion;
pub mod passkey_attestation;
pub mod passkey_ceremonies;
pub mod password_login;
pub mod passwords;
pub mod profile;
mod request_json;
pub mod session_cookies;
pub mod signing;
pub mod token_authorization;
pub mod token_http;
mod token_runtime;

use std::time::Duration;

use axum::{Json, Router, extract::State, http::StatusCode};
use serde::Serialize;
use sqlx::PgPool;

// Schema revision supported by this build.
pub const SCHEMA_REVISION: &str = "0043";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
struct App {
    environment: String,
    pool: PgPool,
    diagnostics: std::sync::Arc<tokio::sync::Semaphore>,
}

pub async fn application(
    environment: String,
    pool: PgPool,
    interval: Duration,
) -> Result<Router, Box<dyn std::error::Error>> {
    let production = environment == "production";
    let mut provider = discovery::Provider::from_env()?;
    let (browser, cors_origins, redirects) = browser_policy::BrowserPolicy::configured()?;
    let (profile, resources) = profile::routes_with_policy(
        pool.clone(),
        production,
        interval,
        provider.as_mut(),
        Some(browser),
    )
    .await?;
    let token =
        token_http::routes_with_resources(provider.as_ref(), pool.clone(), production, resources)
            .await?;
    let login = login_http::routes_with_redirects(pool.clone(), &environment, redirects)?;
    let methods = login_methods::routes(&environment)?;
    let app = router(environment, pool.clone())
        .merge(profile)
        .merge(token)
        .merge(login)
        .merge(methods)
        .merge(email_link_http::routes(pool)?)
        .merge(discovery::routes(provider));
    cors::apply_origins(app, cors_origins)
}

pub fn router(environment: String, pool: PgPool) -> Router {
    foundation::get_resource("/api/v1/health", liveness)
        .merge(foundation::get_resource("/api/v1/health/ready", readiness))
        .with_state(App {
            environment,
            pool,
            diagnostics: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        })
}

#[derive(Serialize)]
struct Liveness {
    status: &'static str,
    version: &'static str,
    environment: String,
}

async fn liveness(State(app): State<App>) -> Json<Liveness> {
    Json(Liveness {
        status: "healthy",
        version: VERSION,
        environment: app.environment,
    })
}

#[derive(Serialize)]
struct Readiness {
    status: &'static str,
    database: bool,
    migrations: bool,
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

async fn readiness(State(app): State<App>) -> (StatusCode, Json<Readiness>) {
    let (database, detail) = readiness_db::check(&app.pool, &app.diagnostics).await;
    let ready = detail.is_none();
    let body = Readiness {
        status: if ready { "ready" } else { "not_ready" },
        database,
        migrations: ready,
        version: VERSION,
        detail,
    };
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(body),
    )
}
pub mod enrolled_factor;

mod passkey_credentials;

pub mod external_oauth;
pub mod token_revocation;

mod query;
mod readiness_db;

mod admin_audit;
