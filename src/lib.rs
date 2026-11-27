pub mod access_tokens;
pub mod authorization_codes;
pub mod browser_client;
mod browser_http;
pub mod browser_prompt;
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

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde::Serialize;
use sqlx::PgPool;

// Schema revision supported by this build.
pub const SCHEMA_REVISION: &str = "0043";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
struct App {
    environment: String,
    pool: PgPool,
}

pub fn router(environment: String, pool: PgPool) -> Router {
    Router::new()
        .route("/api/v1/health", get(liveness))
        .route("/api/v1/health/ready", get(readiness))
        .with_state(App { environment, pool })
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

async fn check_revision(pool: &PgPool) -> (bool, Option<String>) {
    let Ok(mut connection) = pool.acquire().await else {
        return (false, Some("database unreachable".into()));
    };
    if !matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            sqlx::query("SELECT 1").execute(&mut *connection)
        )
        .await,
        Ok(Ok(_))
    ) {
        return (false, Some("database unreachable".into()));
    }

    let revisions =
        sqlx::query_scalar::<_, String>("SELECT version_num FROM alembic_version LIMIT 2")
            .fetch_all(&mut *connection);
    let detail = match tokio::time::timeout(Duration::from_secs(2), revisions).await {
        Ok(Ok(rows)) if rows.as_slice() == [SCHEMA_REVISION] => None,
        Ok(Ok(rows)) if rows.len() == 1 => Some(format!(
            "schema at '{}', expected '{}'",
            rows[0], SCHEMA_REVISION
        )),
        Ok(Ok(rows)) if rows.is_empty() => {
            Some(format!("schema at None, expected '{}'", SCHEMA_REVISION))
        }
        _ => Some("migration state unreadable".into()),
    };
    (true, detail)
}

async fn readiness(State(app): State<App>) -> (StatusCode, Json<Readiness>) {
    let (database, detail) = check_revision(&app.pool).await;
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
