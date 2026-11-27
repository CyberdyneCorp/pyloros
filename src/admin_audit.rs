//! Append OAuth administration events to the shared audit chain.
use crate::grant_response::SessionOrigin;
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use std::fmt::Write;
use uuid::Uuid;

fn canonical_digest(mut fields: Value) -> String {
    fields.sort_all_objects();
    format!("{:x}", Sha256::digest(ascii_json(&fields).as_bytes()))
}

pub(crate) fn ascii_json(value: &Value) -> String {
    let mut ascii = String::new();
    for c in value.to_string().chars() {
        if c < '\u{7f}' {
            ascii.push(c);
        } else {
            for unit in c.encode_utf16(&mut [0; 2]) {
                write!(ascii, "\\u{unit:04x}").expect("write to string");
            }
        }
    }
    ascii
}

pub(crate) async fn append_client_action(
    tx: &mut Transaction<'_, Postgres>,
    action: &str,
    actor: Option<(Uuid, Option<&str>)>,
    target: &str,
    meta: Value,
    origin: SessionOrigin<'_>,
) -> Result<(), sqlx::Error> {
    append(tx, action, actor, ("oauth_client", target), meta, origin).await
}

pub(crate) async fn append(
    tx: &mut Transaction<'_, Postgres>,
    action: &str,
    actor: Option<(Uuid, Option<&str>)>,
    target: (&str, &str),
    meta: Value,
    origin: SessionOrigin<'_>,
) -> Result<(), sqlx::Error> {
    append_record(
        tx,
        action,
        actor,
        Some((target.0, Some(target.1))),
        meta,
        origin,
    )
    .await
}

pub(crate) async fn append_record(
    tx: &mut Transaction<'_, Postgres>,
    action: &str,
    actor: Option<(Uuid, Option<&str>)>,
    target: Option<(&str, Option<&str>)>,
    meta: Value,
    origin: SessionOrigin<'_>,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    let (target_type, target) = target.unzip();
    let target = target.flatten();
    sqlx::query("INSERT INTO audit_chain_head (id,head_hash) VALUES (1,repeat('0',64)) ON CONFLICT(id) DO NOTHING")
        .execute(&mut **tx).await?;
    let previous = sqlx::query_scalar::<_, String>(
        "SELECT head_hash FROM audit_chain_head WHERE id=1 FOR UPDATE",
    )
    .fetch_one(&mut **tx)
    .await?;
    let id = Uuid::new_v4();
    let ip = origin.ip.map(|v| v.to_string());
    let actor_id = actor.map(|(id, _)| id);
    let actor_email = actor.and_then(|(_, email)| email);
    let digest = canonical_digest(
        json!({"action":action,"actor_email":actor_email,"actor_user_id":actor_id,
        "target_id":target,"target_type":target_type,"id":id,"metadata":meta,"ip_address":ip,"user_agent":origin.user_agent,
        "prev_hash":previous,"created_at":now.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()}),
    );
    sqlx::query(
        "INSERT INTO admin_action_logs (id,action,target_type,target_id,extra_metadata,ip_address,user_agent,created_at,prev_hash,row_hash,actor_user_id,actor_email)
         VALUES ($1,$2,$12,$3,$4,$5::text::inet,$6,$7,$8,$9,$10,$11)",
    )
    .bind(id)
    .bind(action)
    .bind(target)
    .bind(meta)
    .bind(ip)
    .bind(origin.user_agent)
    .bind(now)
    .bind(previous)
    .bind(&digest)
    .bind(actor_id)
    .bind(actor_email)
    .bind(target_type)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE audit_chain_head SET head_hash=$1 WHERE id=1")
        .bind(digest)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn audit_creation_time_precedes_wait_for_chain_serialization() -> Result<(), sqlx::Error>
    {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut writer = pool.begin().await?;
        let mut gate = pool.begin().await?;
        let key = Uuid::new_v4().as_u128() as i64;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *writer)
            .await?;
        sqlx::raw_sql(&format!(
            "CREATE TEMP TABLE audit_chain_head(id int primary key, head_hash text);
             CREATE TEMP TABLE admin_action_logs(id uuid,action text,target_type text,target_id text,
               extra_metadata jsonb,ip_address inet,user_agent text,created_at timestamptz,
               prev_hash text,row_hash text,actor_user_id uuid,actor_email text);
             CREATE FUNCTION pg_temp.wait_on_head() RETURNS trigger LANGUAGE plpgsql AS
               $$ BEGIN PERFORM pg_advisory_xact_lock({key}::bigint); RETURN NEW; END $$;
             CREATE TRIGGER wait_on_head BEFORE INSERT ON audit_chain_head
               FOR EACH ROW EXECUTE FUNCTION pg_temp.wait_on_head()"
        )).execute(&mut *writer).await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(key)
            .execute(&mut *gate)
            .await?;
        let append = async {
            append_record(
                &mut writer,
                "test",
                None,
                None,
                json!({}),
                SessionOrigin {
                    ip: None,
                    user_agent: None,
                },
            )
            .await?;
            sqlx::query_scalar::<_, chrono::DateTime<Utc>>(
                "SELECT created_at FROM pg_temp.admin_action_logs",
            )
            .fetch_one(&mut *writer)
            .await
        };
        let release = async {
            loop {
                let blocked: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT FROM pg_locks WHERE pid=$1 AND NOT granted)",
                )
                .bind(pid)
                .fetch_one(&mut *gate)
                .await?;
                if blocked {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            let observed = Utc::now();
            gate.commit().await?;
            Ok::<_, sqlx::Error>(observed)
        };
        let (created, observed) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::try_join!(append, release)
        })
        .await
        .expect("audit insert reached lock")?;
        assert!(created <= observed);
        Ok(())
    }

    #[test]
    fn unicode_registration_metadata_preserves_the_chain_digest() {
        let content = json!({"nested":{"z":1,"a":2},"label":"Δ 🏛"});
        assert_eq!(
            canonical_digest(content),
            "edb09f4a065cf69cda395d3cecfd5ef4323c799de7a5ad53ee579cc4da25c2f0"
        );
    }
}
