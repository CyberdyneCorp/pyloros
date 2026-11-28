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
    let row = sqlx::query(include_str!("claim.sql"))
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
    if value["status"] == "success" {
        let output = value["output"]
            .as_str()
            .and_then(super::super::v1_output)
            .map(|s| s.replace('\0', "�"));
        return ("success", output, None);
    }
    let key = if value["status"] == "error" {
        "output"
    } else {
        "error"
    };
    let error = value[key].as_str().map(|s| s.replace('\0', "�"));
    let status = if error
        .as_deref()
        .is_some_and(|message| message.to_ascii_lowercase().contains("timeout"))
    {
        "timeout"
    } else {
        "failed"
    };
    (status, None, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn account_event_claim_orders_stored_fields_after_checking_current_privacy() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE hooks(id int, receive_pii bool);
            CREATE TEMP TABLE pyloros_hook_artifacts(sha256 text, component bytea);
            CREATE TEMP TABLE pyloros_hook_deliveries(id int, hook_id int, hook_name text,
              event_type text, user_id uuid, payload jsonb, timeout_seconds int,
              sha256 text, available_at timestamptz);
            INSERT INTO hooks VALUES(1, true);
            INSERT INTO pyloros_hook_artifacts VALUES('digest', '');
            INSERT INTO pyloros_hook_deliveries VALUES(1,1,'display','user_registered',NULL,
              '{}',1,'digest',now())",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let registrations = (
            "user_registered",
            r#"{"event_type": "user_registered", "user_id": "subject"}"#,
            r#"{"email": "person@example.org", "address": "addr", "event_type": "user_registered", "user_id": "subject"}"#,
        );
        let logins = (
            "user_logged_in",
            r#"{"event_type": "user_logged_in", "user_id": "subject"}"#,
            r#"{"email": "person@example.org", "user_agent": null, "ip": null, "event_type": "user_logged_in", "user_id": "subject"}"#,
        );
        // Entitlement fields are public event data for both privacy settings.
        let grant = r#"{"product_key": "books", "plan": null, "entitlement_id": "grant", "source": "admin", "organization_id": "org", "event_type": "entitlement_granted", "user_id": null}"#;
        let revoke = r#"{"product_key": "books", "plan": null, "entitlement_id": "grant", "event_type": "entitlement_revoked", "user_id": "subject"}"#;
        for (event, public, private) in [
            registrations,
            logins,
            ("entitlement_granted", grant, grant),
            ("entitlement_revoked", revoke, revoke),
        ] {
            for (stored, enabled, expected) in [
                (private, true, private),
                (private, false, public),
                (public, true, public),
                (public, false, public),
            ] {
                sqlx::query("UPDATE pyloros_hook_deliveries SET event_type=$1, payload=$2::jsonb")
                    .bind(event)
                    .bind(stored)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                sqlx::query("UPDATE hooks SET receive_pii=$1")
                    .bind(enabled)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                let row = sqlx::query(include_str!("claim.sql"))
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                assert_eq!(row.get::<&str, _>("payload"), expected);
            }
        }
    }

    #[test]
    fn history_distinguishes_reported_timeouts_from_other_errors() {
        for (result, status, message) in [
            (
                json!({"status":"error","output":"ValueError: service TIMEOUT"}),
                "timeout",
                "ValueError: service TIMEOUT",
            ),
            (
                json!({"status":"error","output":"timed out"}),
                "failed",
                "timed out",
            ),
            (
                json!({"status":"failed","error":"Timeout waiting"}),
                "timeout",
                "Timeout waiting",
            ),
            (
                json!({"status":"failed","error":"Hook execution failed"}),
                "failed",
                "Hook execution failed",
            ),
        ] {
            assert_eq!(history(&result), (status, None, Some(message.into())));
        }
        assert_eq!(
            history(&json!({"status":"success","output":"timeout"})),
            ("success", Some("timeout".into()), None)
        );
    }

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
