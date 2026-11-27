//! External identity provider authorization and shared callback state.
mod input;
mod provider;
pub mod state;

use crate::{config::flag, login_http::problem};
use axum::{
    Json, Router,
    extract::{Path, RawQuery, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use input::Start;
use provider::Provider;
use serde_json::json;
use sqlx::PgPool;
use std::{
    collections::{BTreeSet, HashMap},
    env,
    error::Error,
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

type Redirects = BTreeSet<String>;

struct Service {
    pool: PgPool,
    providers: HashMap<&'static str, Provider>,
    allowed: watch::Receiver<Redirects>,
    ttl: i64,
    cli: bool,
    forbidden_stub: bool,
}

pub async fn routes(
    pool: PgPool,
    environment: &str,
    interval: Duration,
) -> Result<Router, Box<dyn Error>> {
    let stub = flag("OAUTH_STUB_ENABLED")?;
    let providers = ["google", "microsoft"]
        .into_iter()
        .filter_map(|name| Provider::configured(name, stub).map(|p| (name, p)))
        .collect();
    let raw = env::var("OAUTH_CLIENT_REDIRECT_ALLOWLIST").unwrap_or_default();
    let entries: Vec<String> = if raw.trim_start().starts_with('[') {
        serde_json::from_str(&raw)?
    } else {
        raw.split(',').map(str::to_owned).collect()
    };
    let base: Redirects = entries
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let (updates, allowed) = watch::channel(base.clone());
    if !interval.is_zero() {
        refresh(&pool, &base, &updates).await;
        let pool = pool.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _=updates.closed()=>break,
                    _=tokio::time::sleep(interval)=>refresh(&pool,&base,&updates).await
                }
            }
        });
    }
    let service = Service {
        pool,
        providers,
        allowed,
        ttl: crate::token_runtime::number("OAUTH_STATE_TTL_SECONDS", 600)?,
        cli: flag("CLI_LOGIN_ENABLED")?,
        forbidden_stub: stub && environment == "production",
    };
    Ok(Router::new()
        .route("/api/v1/auth/oauth/{provider}", any(start))
        .with_state(Arc::new(service)))
}

async fn refresh(pool: &PgPool, base: &Redirects, updates: &watch::Sender<Redirects>) {
    match sqlx::query_scalar::<_, String>(
        "SELECT fragment_redirect_uris FROM oauth_web_origins WHERE active",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => {
            let mut allowed = base.clone();
            for row in rows {
                allowed.extend(row.split_whitespace().map(str::to_owned));
            }
            updates.send_replace(allowed);
        }
        Err(_) => eprintln!("could not refresh OAuth frontend redirect registry"),
    }
}

async fn start(
    State(service): State<Arc<Service>>,
    Path(name): Path<String>,
    RawQuery(raw): RawQuery,
    method: Method,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    if service.forbidden_stub {
        return internal();
    }
    let input = match Start::parse(raw.as_deref().unwrap_or_default()) {
        Ok(input) => input,
        Err(issues) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":issues})),
            )
                .into_response();
        }
    };
    if input.mode == "cli" && !service.cli {
        return problem(StatusCode::BAD_REQUEST, "CLI login is disabled");
    }
    let Some(provider) = service.providers.get(name.as_str()) else {
        return problem(StatusCode::BAD_REQUEST, "Unknown OAuth provider");
    };
    if let Err(message) = input.validate(&service.allowed.borrow()) {
        return problem(StatusCode::BAD_REQUEST, message);
    }
    let (port, challenge) = if input.mode == "cli" {
        (input.port, input.challenge)
    } else {
        (None, None)
    };
    let instructions = state::ReturnInstructions {
        return_mode: input.mode,
        frontend_redirect: input.target,
        cli_port: port,
        code_challenge: challenge,
    };
    let Ok(state) = instructions.issue(&service.pool, &name, service.ttl).await else {
        return internal();
    };
    let url = provider.authorization_url(state);
    if input.redirect {
        crate::browser_http::redirect(url)
    } else {
        Json(json!({"authorization_url":url,"state":state})).into_response()
    }
}

fn internal() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
