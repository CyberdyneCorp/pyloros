use super::*;
use sqlx::{Acquire, Row};
use tokio::{
    task::JoinHandle,
    time::{Duration, Instant, sleep, timeout},
};

pub struct ComponentHookWorker(JoinHandle<()>);
impl ComponentHookWorker {
    pub fn start(pool: PgPool) -> Result<Option<Self>, Box<dyn Error>> {
        let store = Producer::Store.enabled()?;
        let administrator = Producer::Administrator.enabled()?;
        let role = Producer::Role.enabled()?;
        let registration = Producer::Registration.enabled()?;
        let login = Producer::Login.enabled()?;
        let erasure = Producer::Erasure.enabled()?;
        let any_producer = store || administrator || role || registration || login || erasure;
        if !config::flag_with_default("HOOKS_ENABLED", true)?
            || !config::flag_with_default("PYLOROS_COMPONENT_WORKER_ENABLED", any_producer)?
        {
            return Ok(None);
        }
        Ok(Some(Self(tokio::spawn(async move {
            loop {
                match deliver(&pool).await {
                    Ok(true) => continue,
                    Ok(false) => sleep(Duration::from_millis(250)).await,
                    Err(error) => {
                        eprintln!("component hook delivery failed: {error}");
                        sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        }))))
    }
}
impl Drop for ComponentHookWorker {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn deliver(pool: &PgPool) -> sqlx::Result<bool> {
    let Ok(_slot) = dry_run::WORKERS.try_acquire() else {
        return Ok(false);
    };
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT q.id,q.hook_id,q.hook_name,q.event_type,
        CASE WHEN q.event_type='user_deleted' THEN (q.payload->>'user_id')::uuid ELSE q.user_id END AS user_id,
        (CASE WHEN q.event_type IN ('user_registered','user_logged_in') AND NOT h.receive_pii
          THEN jsonb_build_object('event_type',q.event_type,'user_id',q.user_id)
          ELSE q.payload END)::text AS payload,
        q.timeout_seconds,a.component FROM pyloros_hook_deliveries q
        JOIN hooks h ON h.id=q.hook_id JOIN pyloros_hook_artifacts a ON a.sha256=q.sha256 WHERE available_at<=clock_timestamp()
        ORDER BY available_at,q.id LIMIT 1 FOR UPDATE OF q SKIP LOCKED",
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else { return Ok(false) };
    let id: Uuid = row.try_get("id")?;
    let seconds: i32 = row.try_get("timeout_seconds")?;
    let payload: &str = row.try_get("payload")?;
    let started = Instant::now();
    let result = if payload.len() > dry_run::MAX_EVENT {
        (
            "failed",
            None,
            Some("Hook event exceeds 64 KiB".to_string()),
        )
    } else {
        match timeout(
            Duration::from_secs(seconds as u64),
            dry_run::invoke(row.try_get("component")?, payload.as_bytes()),
        )
        .await
        {
            Err(_) => ("timeout", None, Some("Hook execution timed out".into())),
            Ok(Ok(value)) => history(&value),
            Ok(Err(_)) => {
                retry(tx, id).await?;
                return Ok(true);
            }
        }
    };
    let (status, output, error) = result;
    let event: &str = row.try_get("event_type")?;
    let mut history_tx = tx.begin().await?;
    let insert = sqlx::query(
        "INSERT INTO hook_executions(id,hook_id,hook_name,event_type,user_id,status,output,error_message,execution_time_ms,context_snapshot)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,jsonb_build_object('event',$4::text))",
    )
    .bind(id)
    .bind(row.try_get::<Uuid,_>("hook_id")?)
    .bind(row.try_get::<&str,_>("hook_name")?)
    .bind(event)
    .bind(row.try_get::<Option<Uuid>,_>("user_id")?)
    .bind(status)
    .bind(output)
    .bind(error)
    .bind(started.elapsed().as_millis() as i32)
    .execute(&mut *history_tx).await;
    // A deferred history trigger can reject a row at commit. Check it while
    // the savepoint can still be rolled back and another delivery can advance.
    let checked = match insert {
        Ok(_) => {
            sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
                .execute(&mut *history_tx)
                .await
        }
        Err(error) => Err(error),
    };
    if let Err(error) = checked {
        history_tx.rollback().await?;
        retry(tx, id).await?;
        return Err(error);
    }
    history_tx.commit().await?;
    sqlx::query("DELETE FROM pyloros_hook_deliveries WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

async fn retry(mut tx: Transaction<'_, Postgres>, id: Uuid) -> sqlx::Result<()> {
    sqlx::query("UPDATE pyloros_hook_deliveries SET available_at=clock_timestamp()+interval '5 seconds' WHERE id=$1")
        .bind(id).execute(&mut *tx).await?;
    tx.commit().await
}

fn history(value: &Value) -> (&'static str, Option<String>, Option<String>) {
    let text = |key: &str| value[key].as_str().map(|s| s.replace('\0', "�"));
    match value["status"].as_str() {
        Some("success") => (
            "success",
            value["output"]
                .as_str()
                .and_then(super::super::v1_output)
                .map(|s| s.replace('\0', "�")),
            None,
        ),
        Some("error") => ("failed", None, text("output")),
        _ => ("failed", None, text("error")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_history_preserves_whitespace_and_limits_output_by_character() {
        for (output, expected) in [
            (String::new(), None),
            (" \n".into(), Some(" \n".into())),
            ("雪".repeat(10_000) + "tail", Some("雪".repeat(10_000))),
        ] {
            assert_eq!(
                history(&json!({"status":"success","output":output})),
                ("success", expected, None)
            );
        }
    }
}
