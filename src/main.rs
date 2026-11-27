use std::{env, error::Error, time::Duration};

use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(2))
        .connect_lazy(&env::var("DATABASE_URL")?)?;
    let listener =
        TcpListener::bind(env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8000".into()))
            .await?;
    eprintln!("Pyloros listening on {}", listener.local_addr()?);
    let environment = env::var("APP_ENV").unwrap_or_else(|_| "dev".into());
    let secure_transport = pyloros::session_cookies::secure_transport(environment == "production")?;
    let mut provider = pyloros::discovery::Provider::from_env()?;
    let seconds: u64 = env::var("OAUTH_REGISTRY_REFRESH_SECONDS")
        .unwrap_or_else(|_| "30".into())
        .parse()?;
    if let Some(issuer) = &mut provider {
        issuer
            .refresh_scopes(pool.clone(), Duration::from_secs(seconds))
            .await;
    }
    let token =
        pyloros::token_http::routes(provider.as_ref(), pool.clone(), environment == "production")
            .await?;
    let profile = pyloros::profile::routes(pool.clone(), environment == "production")?;
    let login_methods = pyloros::login_methods::routes(&environment)?;
    let login = pyloros::login_http::routes_with_external(
        pool.clone(),
        &environment,
        Duration::from_secs(seconds),
    )
    .await?;
    let app = pyloros::router(environment, pool.clone())
        .merge(token)
        .merge(login_methods)
        .merge(login)
        .merge(pyloros::email_link_http::routes(pool.clone())?)
        .merge(profile);
    let app = app.merge(pyloros::discovery::routes(provider));
    let app = pyloros::cors::apply(app, pool, Duration::from_secs(seconds)).await?;
    let app = app.layer(axum::middleware::from_fn(
        pyloros::profile::limit_passkey_body,
    ));
    axum::serve(
        listener,
        pyloros::headers::apply(app, secure_transport)
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
