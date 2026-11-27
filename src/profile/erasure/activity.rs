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
        if rows.is_empty() {
            return Ok(count);
        }
        for (id, mut event) in rows {
            redact(&mut event, &key, ids, &needles);
            event.sort_all_objects();
            let hash = format!("{:x}", Sha256::digest(event.to_string().as_bytes()));
            sqlx::query(
                "UPDATE auth_events SET subject_format=$2->>'subject_format',
                subject_identifier=$2->>'subject_identifier',subject_email=$2->>'subject_email',
                subject_issuer=$2->>'subject_issuer',ip_address=($2->>'ip_address')::inet,
                user_agent=$2->>'user_agent',details=$2->'details', content_hash=$3 WHERE id=$1",
            )
            .bind(id)
            .bind(event)
            .bind(hash)
            .execute(&mut **tx)
            .await?;
            cursor = Some(id);
            count += 1;
        }
    }
}
fn is_subject(event: &Value, key: &str, ids: &Identifiers) -> bool {
    let id = event["subject_identifier"].as_str().unwrap_or("");
    if event["subject_user_id"] == key
        || id == key
        || event["subject_email"]
            .as_str()
            .is_some_and(|s| ids.emails.contains(&s.to_lowercase()))
    {
        return true;
    }
    match event["subject_format"].as_str() {
        Some("iss_sub") => ids.social.contains(&(
            event["subject_issuer"].as_str().unwrap_or("").to_owned(),
            id.to_owned(),
        )),
        Some("did") => ids
            .wallets
            .contains(&id.rsplit(':').next().unwrap_or("").to_lowercase()),
        _ => false,
    }
}
fn redact(event: &mut Value, key: &str, ids: &Identifiers, needles: &[String]) {
    let about = is_subject(event, key, ids);
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
