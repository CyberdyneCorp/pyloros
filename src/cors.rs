//! Credentialed cross-origin requests from operator-approved browser clients.
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use sqlx::PgPool;
use std::{collections::BTreeSet, env, error::Error, time::Duration};
use tokio::sync::watch;

type Origins = BTreeSet<String>;
const METHODS: &str = "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT";

pub async fn apply(
    router: Router,
    pool: PgPool,
    interval: Duration,
) -> Result<Router, Box<dyn Error>> {
    let raw = env::var("CORS_ALLOWED_ORIGINS").unwrap_or_else(|_| "http://localhost:3001".into());
    let entries: Vec<String> = if raw.trim_start().starts_with('[') {
        serde_json::from_str(&raw)?
    } else {
        raw.split(',').map(str::trim).map(str::to_string).collect()
    };
    let base: Origins = entries.into_iter().filter(|v| !v.is_empty()).collect();
    if base.iter().any(|v| v.trim() == "*") {
        return Err("CORS_ALLOWED_ORIGINS requires explicit origins".into());
    }
    let (updates, state) = watch::channel(base.clone());
    if !interval.is_zero() {
        refresh(&pool, &base, &updates).await;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _=updates.closed()=>break,
                    _=tokio::time::sleep(interval)=>refresh(&pool,&base,&updates).await,
                }
            }
        });
    }
    let cookie = crate::session_cookies::csrf_name()?;
    let csrf = crate::csrf::Policy::new(state.clone(), cookie);
    Ok(router
        .layer(middleware::from_fn_with_state(state, policy))
        .layer(middleware::from_fn_with_state(csrf, crate::csrf::check)))
}

async fn refresh(pool: &PgPool, base: &Origins, updates: &watch::Sender<Origins>) {
    match sqlx::query_scalar::<_, String>(
        "SELECT origin FROM oauth_web_origins WHERE active AND cors",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => {
            let mut origins = base.clone();
            origins.extend(rows.into_iter().filter(|v| v != "*"));
            updates.send_replace(origins);
        }
        Err(_) => eprintln!("could not refresh browser origin registry"),
    }
}

fn preflight(headers: &HeaderMap, method: &HeaderValue, allowed: bool) -> Response {
    let mut errors = Vec::new();
    if !allowed {
        errors.push("origin")
    }
    if !METHODS.split(", ").any(|m| method == m) {
        errors.push("method")
    }
    if headers.contains_key("access-control-request-private-network") {
        errors.push("private-network")
    }
    let mut res = if errors.is_empty() {
        "OK".into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            format!("Disallowed CORS {}", errors.join(", ")),
        )
            .into_response()
    };
    let out = res.headers_mut();
    out.insert("vary", HeaderValue::from_static("Origin"));
    out.insert(
        "access-control-allow-methods",
        HeaderValue::from_static(METHODS),
    );
    out.insert("access-control-max-age", HeaderValue::from_static("600"));
    if let Some(names) = headers.get("access-control-request-headers") {
        out.insert("access-control-allow-headers", names.clone());
    }
    res
}

async fn policy(
    State(origins): State<watch::Receiver<Origins>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(origin) = req.headers().get("origin").cloned() else {
        return next.run(req).await;
    };
    let allowed = origin.to_str().is_ok_and(|v| origins.borrow().contains(v));
    let mut res = if req.method() == Method::OPTIONS
        && let Some(method) = req.headers().get("access-control-request-method")
    {
        preflight(req.headers(), method, allowed)
    } else {
        let mut res = next.run(req).await;
        res.headers_mut().insert(
            "access-control-expose-headers",
            HeaderValue::from_static("X-CSRF-Token"),
        );
        if allowed {
            res.headers_mut()
                .append("vary", HeaderValue::from_static("Origin"));
        }
        res
    };
    let out = res.headers_mut();
    out.insert(
        "access-control-allow-credentials",
        HeaderValue::from_static("true"),
    );
    if allowed {
        out.insert("access-control-allow-origin", origin);
    }
    res
}
