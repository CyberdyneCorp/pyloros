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
    let cookie_secure = pyloros::config::flag("COOKIE_SECURE")?;
    let force_secure = pyloros::config::flag("FORCE_SECURE_COOKIES")?;
    let secure_transport = environment == "production" || cookie_secure || force_secure;
    let mut provider = pyloros::discovery::Provider::from_env()?;
    if let Some(issuer) = &mut provider {
        let seconds: u64 = env::var("OAUTH_REGISTRY_REFRESH_SECONDS")
            .unwrap_or_else(|_| "30".into())
            .parse()?;
        issuer
            .refresh_scopes(pool.clone(), Duration::from_secs(seconds))
            .await;
    }
    let token =
        pyloros::token_http::routes(provider.as_ref(), pool.clone(), environment == "production")
            .await?;
    let app = pyloros::router(environment, pool).merge(token);
    let app = app.merge(pyloros::discovery::routes(provider));
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
