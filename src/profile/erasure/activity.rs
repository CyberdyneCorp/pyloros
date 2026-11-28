use super::*;
use sha2::{Digest, Sha256};

pub(super) async fn rewrite(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    ids: &Identifiers,
) -> Result<i64, sqlx::Error> {
    let emails: Vec<_> = ids.emails.iter().collect();
    let subjects: Vec<_> = ids.social.iter().map(|(_, s)| s).collect();
    let wallets: Vec<_> = ids
        .wallets
        .iter()
        .map(|w| format!("did:pkh:eip155:%:{w}"))
        .collect();
    let needles = ids.needles();
    let key = user.to_string();
    let mut cursor: Option<Uuid> = None;
    let mut count = 0;
    loop {
        let rows = sqlx::query_as::<_, (Uuid, Value)>(
            "SELECT id, (to_jsonb(e)-'content_hash') || jsonb_build_object(
               'ip_address',host(ip_address),'occurred_at',to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'))
             FROM auth_events e WHERE ($5::uuid IS NULL OR id>$5) AND
             (subject_user_id=$1 OR actor_user_id=$1 OR lower(subject_email)=ANY($2)
              OR subject_identifier=ANY($3) OR subject_identifier LIKE ANY($4))
             ORDER BY id LIMIT 500 FOR UPDATE"
        )
        .bind(user)
        .bind(&emails)
        .bind(&subjects)
        .bind(&wallets)
        .bind(cursor)
        .fetch_all(&mut **tx)
        .await?;
        let Some((last_id, _)) = rows.last() else {
            return Ok(count);
        };
        cursor = Some(*last_id);
        let mut batch = Vec::with_capacity(rows.len());
        for (_, mut event) in rows {
            redact(&mut event, &key, ids, &needles);
            event.sort_all_objects();
            let hash = format!("{:x}", Sha256::digest(event.to_string().as_bytes()));
            event["content_hash"] = Value::String(hash);
            batch.push(event);
        }
        count += persist(tx, batch).await?;
    }
}

async fn persist(
    tx: &mut Transaction<'_, Postgres>,
    batch: Vec<Value>,
) -> Result<i64, sqlx::Error> {
    let expected = batch.len() as u64;
    let result = sqlx::query(
        "UPDATE auth_events AS e SET subject_format=r.subject_format,
         subject_identifier=r.subject_identifier,subject_email=r.subject_email,
         subject_issuer=r.subject_issuer,ip_address=r.ip_address,
         user_agent=r.user_agent,details=r.details,content_hash=r.content_hash
         FROM jsonb_to_recordset($1) AS r(id uuid,subject_format text,subject_identifier text,
             subject_email text,subject_issuer text,ip_address inet,user_agent text,
             details jsonb,content_hash text)
         WHERE e.id=r.id",
    )
    .bind(Value::Array(batch))
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != expected {
        return Err(sqlx::Error::Protocol(
            "Incomplete authentication event rewrite".into(),
        ));
    }
    Ok(expected as i64)
}

fn redact(event: &mut Value, key: &str, ids: &Identifiers, needles: &[String]) {
    let about = subject_identifiers::is_subject(event, key, ids);
    if event["actor_user_id"] == key
        || (about && event["actor_type"] == "user" && event["actor_user_id"].is_null())
    {
        event["ip_address"] = Value::Null;
        event["user_agent"] = Value::Null;
    }
    if about {
        event["subject_format"] = json!("opaque");
        event["subject_identifier"] = json!(key);
        event["subject_issuer"] = Value::Null;
        event["subject_email"] = Value::Null;
    }
    if let Some(details) = event["details"].as_object_mut() {
        for value in details.values_mut() {
            scrub(value, needles);
        }
    }
    event["details"]["pseudonymised"] = json!(true);
}
fn scrub(value: &mut Value, needles: &[String]) {
    match value {
        Value::String(s) => {
            let lower = s.to_lowercase();
            if needles.iter().any(|n| lower.contains(n)) {
                *s = "[erased]".into();
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub(item, needles);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn batch_updates_match_ids_and_detect_a_missing_event() -> sqlx::Result<()> {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::query(
            "CREATE TEMP TABLE auth_events(id uuid PRIMARY KEY, subject_format text,
            subject_identifier text, subject_email text, subject_issuer text, ip_address inet,
            user_agent text, details jsonb, content_hash text)",
        )
        .execute(&mut *tx)
        .await?;
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        sqlx::query("INSERT INTO auth_events(id) VALUES($1),($2)")
            .bind(first)
            .bind(second)
            .execute(&mut *tx)
            .await?;
        let changes = vec![
            json!({"id":second,"details":{"n":2},"content_hash":"second","ip_address":"127.0.0.1"}),
            json!({"id":first,"details":{"n":1},"content_hash":"first","ip_address":null}),
        ];
        assert_eq!(persist(&mut tx, changes).await?, 2);
        let rows = sqlx::query_as::<_, (Uuid, Value, String, Option<String>)>(
            "SELECT id,details,content_hash,host(ip_address) FROM auth_events ORDER BY content_hash")
            .fetch_all(&mut *tx).await?;
        assert_eq!(
            rows,
            vec![
                (first, json!({"n":1}), "first".into(), None),
                (
                    second,
                    json!({"n":2}),
                    "second".into(),
                    Some("127.0.0.1".into())
                ),
            ]
        );
        assert!(matches!(
            persist(&mut tx, vec![json!({"id":Uuid::new_v4()})]).await,
            Err(sqlx::Error::Protocol(_))
        ));
        tx.rollback().await
    }
}
