//! PostgreSQL-backed outbound notifications.
use crate::key_encryption::KeyEncryptionKey;
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream};
use rand::Rng;
use sqlx::PgPool;
use std::{env, error::Error, time::Duration};
use tokio::task::JoinHandle;
use uuid::Uuid;
mod store;
mod transport;
use store::Delivery;

struct Attempt {
    code: Option<i32>,
    error: Option<String>,
    duration_ms: i32,
    excerpt: Option<String>,
}
impl Attempt {
    fn failed(error: String) -> Self {
        Self {
            code: None,
            error: Some(error),
            duration_ms: 0,
            excerpt: None,
        }
    }
}

struct Settings {
    poll: Duration,
    timeout: Duration,
    lease: chrono::Duration,
    batch: i64,
    concurrency: usize,
    insecure: bool,
}
impl Settings {
    fn configured() -> Result<Self, Box<dyn Error>> {
        let batch = env::var("WEBHOOKS_BATCH_SIZE")
            .unwrap_or_else(|_| "50".into())
            .parse::<u32>()?;
        let concurrency = env::var("WEBHOOKS_MAX_CONCURRENCY")
            .unwrap_or_else(|_| "8".into())
            .parse::<u32>()?;
        if batch == 0 || concurrency == 0 {
            return Err("webhook batch size and concurrency must be positive".into());
        }
        let poll = seconds("WEBHOOKS_POLL_INTERVAL_SECONDS", "2")?;
        let timeout = seconds("WEBHOOKS_REQUEST_TIMEOUT_SECONDS", "10")?;
        let lease = timeout
            .checked_mul(batch.div_ceil(concurrency))
            .and_then(|d| d.checked_add(Duration::from_secs(30)))
            .ok_or("webhook lease too long")?;
        Ok(Self {
            poll,
            timeout,
            lease: chrono::Duration::from_std(lease)?,
            batch: batch.into(),
            concurrency: concurrency as usize,
            insecure: crate::config::insecure_webhook_http()?,
        })
    }
}
fn seconds(name: &str, default: &str) -> Result<Duration, Box<dyn Error>> {
    let seconds = env::var(name)
        .unwrap_or_else(|_| default.into())
        .parse::<f64>()?;
    let duration = Duration::try_from_secs_f64(seconds)?;
    if duration.is_zero() {
        return Err(format!("{name} must be positive").into());
    }
    Ok(duration)
}

pub struct Worker(JoinHandle<()>);
impl Worker {
    pub fn start(pool: PgPool) -> Result<Option<Self>, Box<dyn Error>> {
        if !crate::config::flag_with_default("WEBHOOKS_ENABLED", true)?
            || !crate::config::flag_with_default("PYLOROS_WEBHOOK_WORKER_ENABLED", true)?
        {
            return Ok(None);
        }
        let settings = Settings::configured()?;
        let key = env::var("MASTER_KEY")
            .ok()
            .map(|v| KeyEncryptionKey::new(&v))
            .transpose()?;
        Ok(Some(Self(tokio::spawn(run(pool, settings, key)))))
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.abort()
    }
}

async fn run(pool: PgPool, settings: Settings, key: Option<KeyEncryptionKey>) {
    loop {
        match cycle(&pool, &settings, key.as_ref()).await {
            Ok(n) if n as i64 == settings.batch => continue,
            Ok(_) => {}
            Err(e) => eprintln!("Webhook claim failed: {e}"),
        }
        tokio::time::sleep(settings.poll).await;
    }
}
async fn cycle(
    pool: &PgPool,
    settings: &Settings,
    key: Option<&KeyEncryptionKey>,
) -> sqlx::Result<usize> {
    let now = Utc::now();
    let until = now
        .checked_add_signed(settings.lease)
        .ok_or_else(|| sqlx::Error::Protocol("webhook lease exceeds timestamp range".into()))?;
    let rows = store::claim(pool, now, until, settings.batch).await?;
    let count = rows.len();
    stream::iter(rows)
        .for_each_concurrent(settings.concurrency, |d| async move {
            let at = Utc::now();
            let result = transport::send(&d, key, at, settings).await;
            if let Err(e) = store::record(pool, &d, at, result).await {
                eprintln!("Webhook attempt {} could not be recorded: {e}", d.id);
            }
        })
        .await;
    Ok(count)
}
