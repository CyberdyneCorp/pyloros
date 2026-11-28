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
    let mut inspection = env::args_os().skip(1);
    match inspection.next().as_deref().and_then(|arg| arg.to_str()) {
        Some("--inspect-iam-receipt") => return inspect_receipt(inspection).await,
        Some("--inspect-iam-membership") => {
            let args = inspection
                .map(|arg| arg.into_string().map_err(|_| "invalid membership argument"))
                .collect::<Result<Vec<_>, _>>()?;
            let [contract, group, identity, block] = args.as_slice() else {
                return Err(
                    "expected contract address, group ID, identity token ID and block hash".into(),
                );
            };
            let report =
                pyloros::chain_settings::inspect_membership(contract, group, identity, block)
                    .await?;
            println!("{}", serde_json::to_string(&report)?);
            return Ok(ExitCode::SUCCESS);
        }
        _ => {}
    }
    let mut fixture = env::args_os().skip(1);
    if fixture.next().as_deref() == Some(std::ffi::OsStr::new("--check-hook-fixture")) {
        let paths: Vec<std::path::PathBuf> = fixture.map(Into::into).collect();
        let [component, event, expected] = paths.as_slice() else {
            return Err("expected component, event JSON, and expected outcome paths".into());
        };
        let digest = pyloros::profile::check_hook_fixture(component, event, expected).await?;
        println!("{digest}");
        return Ok(ExitCode::SUCCESS);
    }
    let pool = PgPoolOptions::new()
        .max_connections(15)
        .acquire_timeout(Duration::from_secs(2))
        .connect_lazy(&env::var("DATABASE_URL")?)?;
    let mut args = env::args_os().skip(1);
    let command = args.next();
    match command.as_deref().and_then(|name| name.to_str()) {
        Some("--check-db-writer-mode") => {
            if args.next().is_some() {
                return Err("writer mode takes no arguments".into());
            }
            return check_writer_mode(&pool).await;
        }
        Some("--check-hook-bindings") => {
            let report = hook_inventory::read(&pool, &hook_events(args)?).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(coverage_status(report.active_unbound == 0));
        }
        Some("--inspect-hook-delivery") => {
            let id = args.next().ok_or("expected a delivery UUID")?;
            if args.next().is_some() {
                return Err("expected one delivery UUID".into());
            }
            let id = id.to_str().ok_or("invalid delivery UUID")?.parse()?;
            let report = hook_inventory::delivery(&pool, id).await?;
            println!("{}", serde_json::to_string(&report)?);
            return Ok(ExitCode::SUCCESS);
        }
        Some("--check-hook-queue") => {
            let pending = hook_inventory::pending(&pool, &hook_events(args)?).await?;
            println!("{}", serde_json::json!({ "pending": pending }));
            return Ok(coverage_status(pending == 0));
        }
        _ => {}
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

async fn check_writer_mode(pool: &sqlx::PgPool) -> Result<ExitCode, Box<dyn Error>> {
    let mode: String = sqlx::query_scalar(
        "SELECT CASE
            WHEN pg_catalog.pg_is_in_recovery() THEN 'standby'
            WHEN pg_catalog.current_setting('transaction_read_only')::boolean THEN 'read-only primary'
            ELSE 'writable primary'
         END",
    )
    .fetch_one(pool)
    .await?;
    println!("{mode}");
    Ok(coverage_status(mode == "writable primary"))
}

fn hook_events(
    args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<Vec<&'static str>, Box<dyn Error>> {
    let mut selected = Vec::new();
    for arg in args {
        let name = arg
            .to_str()
            .and_then(|name| {
                pyloros::profile::HOOK_EVENTS
                    .iter()
                    .find(|&&event| event == name)
            })
            .ok_or_else(|| {
                format!(
                    "expected hook events from {}",
                    pyloros::profile::HOOK_EVENTS.join(", ")
                )
            })?;
        selected.push(*name);
    }
    Ok(selected)
}

fn coverage_status(complete: bool) -> ExitCode {
    if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

async fn inspect_receipt(
    mut receipt: impl Iterator<Item = std::ffi::OsString>,
) -> Result<ExitCode, Box<dyn Error>> {
    let hash = receipt.next().ok_or("expected one transaction hash")?;
    let hash = hash.to_str().ok_or("invalid transaction hash")?;
    let report = match (receipt.next().as_deref(), receipt.next()) {
        (None, None) => pyloros::chain_settings::inspect_receipt(hash).await?,
        (Some(flag), None) if flag == "--wait" => {
            pyloros::chain_settings::wait_for_receipt(hash).await?
        }
        _ => return Err("expected a transaction hash and optional --wait".into()),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(if report.outcome == "reported_success" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}
