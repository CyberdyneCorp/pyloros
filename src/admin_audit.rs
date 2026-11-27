//! Append OAuth administration events to the shared audit chain.
use crate::grant_response::SessionOrigin;
use chrono::Utc;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use std::fmt::Write;
use uuid::Uuid;

fn sorted_digest(value: &impl serde::Serialize) -> Result<String, serde_json::Error> {
    let encoded = serde_json::to_string(value)?;
    Ok(format!("{:x}", Sha256::digest(ascii(&encoded))))
}

pub(crate) fn ascii_json(value: &Value) -> String {
    ascii(&value.to_string())
}

fn ascii(text: &str) -> String {
    let mut ascii = String::new();
    for c in text.chars() {
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
    append_actor_record(tx, action, Actor::User(actor), target, meta, origin).await
}

pub(crate) async fn append_actor_record(
    tx: &mut Transaction<'_, Postgres>,
    action: &str,
    actor: Actor<'_>,
    target: Option<(&str, Option<&str>)>,
    meta: Value,
    origin: SessionOrigin<'_>,
) -> Result<(), sqlx::Error> {
    let mut meta = meta;
    meta.sort_all_objects();
    append_sorted_record(tx, action, actor, target, &meta, origin).await
}

#[derive(Clone, Copy)]
pub(crate) enum Actor<'a> {
    User(Option<(Uuid, Option<&'a str>)>),
    Client(&'a str),
}

// The metadata must serialize in sorted key order for the shared audit hash.
pub(crate) async fn append_sorted_record<T: serde::Serialize + Sync>(
    tx: &mut Transaction<'_, Postgres>,
    action: &str,
    actor: Actor<'_>,
    target: Option<(&str, Option<&str>)>,
    meta: &T,
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
    let (actor_type, actor_id, actor_email, actor_client_id) = match actor {
        Actor::User(user) => (
            "user",
            user.map(|(id, _)| id),
            user.and_then(|(_, email)| email),
            None,
        ),
        Actor::Client(client) => ("client", None, None, Some(client)),
    };
    #[derive(serde::Serialize)]
    struct Record<'a, T> {
        action: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        actor_client_id: Option<&'a str>,
        actor_email: Option<&'a str>,
        actor_user_id: Option<Uuid>,
        created_at: String,
        id: Uuid,
        ip_address: Option<&'a str>,
        metadata: &'a T,
        prev_hash: &'a str,
        target_id: Option<&'a str>,
        target_type: Option<&'a str>,
        user_agent: Option<&'a str>,
    }
    let record = Record {
        action,
        actor_client_id,
        actor_email,
        actor_user_id: actor_id,
        created_at: now.format("%Y-%m-%dT%H:%M:%S%.6f").to_string(),
        id,
        ip_address: ip.as_deref(),
        metadata: meta,
        prev_hash: &previous,
        target_id: target,
        target_type,
        user_agent: origin.user_agent,
    };
    let digest = sorted_digest(&record).map_err(|err| sqlx::Error::Encode(err.into()))?;
    sqlx::query(
        "INSERT INTO admin_action_logs (id,action,target_type,target_id,extra_metadata,ip_address,user_agent,created_at,prev_hash,row_hash,actor_user_id,actor_email,actor_type,actor_client_id)
         VALUES ($1,$2,$12,$3,$4,$5::text::inet,$6,$7,$8,$9,$10,$11,$13,$14)",
    )
    .bind(id)
    .bind(action)
    .bind(target)
    .bind(sqlx::types::Json(meta))
    .bind(ip)
    .bind(origin.user_agent)
    .bind(now)
    .bind(previous)
    .bind(&digest)
    .bind(actor_id)
    .bind(actor_email)
    .bind(target_type)
    .bind(actor_type)
    .bind(actor_client_id)
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
               prev_hash text,row_hash text,actor_user_id uuid,actor_type text,actor_client_id text,actor_email text);
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

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn delegated_audit_hash_covers_the_service_client() {
        use sqlx::Row;
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE audit_chain_head(id int primary key,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text,target_type text,target_id text,
            extra_metadata jsonb,ip_address inet,user_agent text,created_at timestamptz,prev_hash text,
            row_hash text,actor_user_id uuid,actor_email text,actor_type text,actor_client_id text);")
            .execute(&mut *tx).await.unwrap();
        append_sorted_record(
            &mut tx,
            "client_permission.create",
            Actor::Client("books"),
            Some(("client_permission", Some("books:read"))),
            &json!({}),
            SessionOrigin {
                ip: None,
                user_agent: None,
            },
        )
        .await
        .unwrap();
        let row = sqlx::query("SELECT * FROM admin_action_logs")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("actor_type"), "client");
        assert_eq!(row.get::<String, _>("actor_client_id"), "books");
        assert!(row.get::<Option<Uuid>, _>("actor_user_id").is_none());
        let time = row.get::<chrono::DateTime<Utc>, _>("created_at");
        let mut signed = json!({
            "action":"client_permission.create","actor_email":null,"actor_user_id":null,
            "created_at":time.format("%Y-%m-%dT%H:%M:%S%.6f").to_string(),
            "id":row.get::<Uuid,_>("id"),"ip_address":null,"metadata":{},
            "prev_hash":"0".repeat(64),"target_id":"books:read",
            "target_type":"client_permission","user_agent":null,"actor_client_id":"books"
        });
        signed.sort_all_objects();
        assert_eq!(
            row.get::<String, _>("row_hash"),
            sorted_digest(&signed).unwrap()
        );
    }

    #[test]
    fn unicode_registration_metadata_preserves_the_chain_digest() {
        let mut content = json!({"nested":{"z":1,"a":2},"label":"Δ 🏛"});
        content.sort_all_objects();
        assert_eq!(
            sorted_digest(&content).unwrap(),
            "edb09f4a065cf69cda395d3cecfd5ef4323c799de7a5ad53ee579cc4da25c2f0"
        );
    }
}
