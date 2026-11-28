mod hook_inventory;

use std::{env, error::Error, process::ExitCode, time::Duration};

use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<ExitCode, Box<dyn Error>> {
    if env::args_os().skip(1).eq(["--print-build-scope-catalog"]) {
        println!(
            "{}",
            serde_json::to_string(&pyloros::config::build_scope_catalog())?
        );
        return Ok(ExitCode::SUCCESS);
    }
    let pool = PgPoolOptions::new()
        .max_connections(15)
        .acquire_timeout(Duration::from_secs(2))
        .connect_lazy(&env::var("DATABASE_URL")?)?;
    if env::args_os().skip(1).eq(["--check-hook-bindings"]) {
        let report = hook_inventory::read(&pool).await?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(if report.active_unbound == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        });
    }
    let listener =
        TcpListener::bind(env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8000".into()))
            .await?;
    eprintln!("Pyloros listening on {}", listener.local_addr()?);
    let environment = env::var("APP_ENV").unwrap_or_else(|_| "dev".into());
    let secure_transport = pyloros::session_cookies::secure_transport(environment == "production")?;
    let seconds: u64 = env::var("OAUTH_REGISTRY_REFRESH_SECONDS")
        .unwrap_or_else(|_| "30".into())
        .parse()?;
    let app = pyloros::application(environment, pool.clone(), Duration::from_secs(seconds)).await?;
    let app = app
        .layer(axum::Extension(listener.local_addr()?))
        .layer(axum::middleware::from_fn(
            pyloros::profile::limit_passkey_body,
        ));
    let _component_hook_worker = pyloros::profile::ComponentHookWorker::start(pool.clone())?;
    let _webhook_worker = pyloros::webhook_worker::Worker::start(pool)?;
    axum::serve(
        listener,
        pyloros::headers::apply(app, secure_transport)
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(ExitCode::SUCCESS)
}
