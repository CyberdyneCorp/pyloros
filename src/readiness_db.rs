//! Database and schema observations for the readiness endpoint.
use sqlx::{ConnectOptions, Connection, Error, PgPool, Postgres, pool::PoolConnection};
use std::{io::ErrorKind, time::Duration};
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout, timeout_at},
};

const POOL_WAIT: Duration = Duration::from_secs(30);

fn connect_error(error: &Error) -> &'static str {
    match error {
        Error::Database(db) => match db.code().as_deref() {
            Some("28000") => "InvalidAuthorizationSpecificationError",
            Some("28P01") => "InvalidPasswordError",
            Some("3D000") => "InvalidCatalogNameError",
            Some("55000") => "ObjectNotInPrerequisiteStateError",
            Some("53300") => "TooManyConnectionsError",
            Some("57P03") => "CannotConnectNowError",
            _ => "DBAPIError",
        },
        Error::Io(io) => match io.kind() {
            ErrorKind::ConnectionRefused => "ConnectionRefusedError",
            ErrorKind::NotFound => "FileNotFoundError",
            ErrorKind::ConnectionReset => "ConnectionResetError",
            ErrorKind::TimedOut => "TimeoutError",
            _ => "OSError",
        },
        Error::PoolTimedOut => "TimeoutError",
        _ => "DBAPIError",
    }
}

async fn diagnose_timeout(pool: &PgPool, diagnostics: &Semaphore) -> &'static str {
    // SQLx retries ECONNREFUSED and transient server errors until its acquisition
    // deadline. A single diagnostic handshake can recover the underlying cause.
    let inspect = async {
        let _permit = diagnostics.acquire().await.ok()?;
        if pool.size() >= pool.options().get_max_connections() {
            return None;
        }
        match pool.connect_options().connect().await {
            Ok(conn) => {
                let _ = conn.close().await;
                None
            }
            Err(error) => Some(connect_error(&error)),
        }
    };
    timeout(Duration::from_secs(1), inspect)
        .await
        .ok()
        .flatten()
        .unwrap_or("TimeoutError")
}

async fn acquire(
    pool: &PgPool,
    diagnostics: &Semaphore,
) -> Result<PoolConnection<Postgres>, &'static str> {
    let deadline = Instant::now() + POOL_WAIT;
    loop {
        match timeout_at(deadline, pool.acquire()).await {
            Ok(Ok(connection)) => return Ok(connection),
            Ok(Err(Error::PoolTimedOut)) if pool.size() >= pool.options().get_max_connections() => {
                continue;
            }
            Ok(Err(Error::PoolTimedOut)) => return Err(diagnose_timeout(pool, diagnostics).await),
            Ok(Err(error)) => return Err(connect_error(&error)),
            Err(_) => return Err("TimeoutError"),
        }
    }
}

fn migration_error(error: &Error) -> &'static str {
    match error {
        Error::Database(db) if db.code().is_some_and(|code| code.starts_with("42")) => {
            "ProgrammingError"
        }
        _ => "DBAPIError",
    }
}

pub(super) async fn check(pool: &PgPool, diagnostics: &Semaphore) -> (bool, Option<String>) {
    let unavailable = |kind| (false, Some(format!("database unreachable: {kind}")));
    let mut connection = match acquire(pool, diagnostics).await {
        Ok(connection) => connection,
        Err(kind) => return unavailable(kind),
    };
    if let Err(error) = sqlx::query("SELECT 1").execute(&mut *connection).await {
        return unavailable(connect_error(&error));
    }
    let revisions =
        sqlx::query_scalar::<_, Option<String>>("SELECT version_num FROM alembic_version LIMIT 2")
            .fetch_all(&mut *connection)
            .await;
    let expected = crate::SCHEMA_REVISION;
    let detail = match revisions.as_deref() {
        Ok([Some(revision)]) if revision == expected => None,
        Ok([Some(revision)]) => Some(format!(
            "schema at {}, expected '{expected}'",
            crate::browser_prompt::quoted_string(revision)
        )),
        Ok([] | [None]) => Some(format!("schema at None, expected '{expected}'")),
        Ok(_) => Some("migration state unreadable: MultipleResultsFound".into()),
        Err(error) => Some(format!(
            "migration state unreadable: {}",
            migration_error(error)
        )),
    };
    (true, detail)
}
