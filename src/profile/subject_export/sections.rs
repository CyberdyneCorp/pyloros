use super::*;
use crate::profile::subject_identifiers::{Identifiers, is_subject};
use serde_json::value::{RawValue, to_raw_value};
use std::collections::BTreeMap;
use std::sync::LazyLock;

#[derive(Deserialize)]
struct Entry {
    table: &'static str,
    strategy: &'static str,
    fields: Vec<&'static str>,
    times: Vec<&'static str>,
}
static INVENTORY: LazyLock<Vec<Entry>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("sections.json")).expect("compiled export inventory")
});
type Record = BTreeMap<String, Box<RawValue>>;

#[derive(serde::Serialize)]
pub(super) struct Section {
    pub table: &'static str,
    on_erasure: &'static str,
    pub rows: Vec<BTreeMap<String, Box<RawValue>>>,
    truncated: bool,
    note: Option<String>,
}

pub(super) async fn collect(
    tx: &mut Transaction<'_, Postgres>,
    settings: &erasure::Settings,
    user: Uuid,
    ids: &Identifiers,
    since: DateTime<Utc>,
) -> sqlx::Result<Vec<Section>> {
    let mut result = Vec::with_capacity(INVENTORY.len());
    for entry in INVENTORY.iter() {
        let mut note = settings.export_note(entry.table).map(str::to_owned);
        let mut rows = Vec::new();
        if let Some(predicate) = entry.predicate(ids) {
            rows = entry.read(tx, user, ids, since, predicate).await?;
        }
        if entry.table == "auth_events" {
            note = Some(format!(
                "Events since {}, newest first. {}",
                since.date_naive(),
                note.unwrap_or_default()
            ));
        }
        let truncated = rows.len() > 1000;
        rows.truncate(1000);
        result.push(Section {
            table: entry.table,
            on_erasure: entry.strategy,
            rows,
            truncated,
            note,
        });
    }
    Ok(result)
}

impl Entry {
    fn predicate(&self, ids: &Identifiers) -> Option<&'static str> {
        match self.table {
            "webhook_events" | "oauth_token_issuance_log" => None,
            "phone_otps" if ids.phones.is_empty() => None,
            "phone_otps" => Some("phone_number=ANY(p.phones)"),
            "users" => Some("id=p.uid"),
            "admin_action_logs" => Some("actor_user_id=p.uid"),
            "auth_challenges" => Some("user_id=p.uid OR lower(wallet_address)=ANY(p.wallets)"),
            "iam_identities" => Some(
                "user_id=p.uid OR lower(email)=ANY(p.emails) OR lower(owner_address)=ANY(p.wallets)",
            ),
            "auth_events" => Some(
                "(subject_user_id=p.uid OR actor_user_id=p.uid OR lower(subject_email)=ANY(p.emails) OR subject_identifier=ANY(p.subjects) OR subject_identifier LIKE ANY(p.dids)) AND occurred_at>=p.since ORDER BY occurred_at DESC",
            ),
            _ => Some("user_id=p.uid"),
        }
    }
    async fn read(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user: Uuid,
        ids: &Identifiers,
        since: DateTime<Utc>,
        predicate: &str,
    ) -> sqlx::Result<Vec<Record>> {
        // Identifiers come exclusively from the compiled, positive field inventory.
        let projection = self
            .fields
            .iter()
            .map(|f| {
                if self.times.contains(f) {
                    format!("encode(timestamptz_send({f}),'hex') AS {f}")
                } else {
                    (*f).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let sql=format!("SELECT row_to_json(r)::text FROM (SELECT {projection} FROM {} CROSS JOIN
            (SELECT $1::uuid AS uid,$2::text[] AS emails,$3::text[] AS phones,$4::text[] AS wallets,$5::text[] AS subjects,$6::text[] AS dids,$7::timestamptz AS since) p
            WHERE {predicate} LIMIT 1001) r",self.table);
        let raw: Vec<String> = sqlx::query_scalar(&sql)
            .bind(user)
            .bind(ids.emails.iter().collect::<Vec<_>>())
            .bind(ids.phones.iter().collect::<Vec<_>>())
            .bind(ids.wallets.iter().collect::<Vec<_>>())
            .bind(ids.social.iter().map(|(_, s)| s).collect::<Vec<_>>())
            .bind(
                ids.wallets
                    .iter()
                    .map(|w| format!("did:pkh:eip155:%:{w}"))
                    .collect::<Vec<_>>(),
            )
            .bind(since)
            .fetch_all(&mut **tx)
            .await?;
        let key = user.to_string();
        raw.into_iter()
            .map(|raw| self.record(raw, &key, ids))
            .collect()
    }
    fn record(&self, raw: String, key: &str, ids: &Identifiers) -> sqlx::Result<Record> {
        crate::stored_json::check_integers(&raw)?;
        let raw = crate::stored_json::project_fractions(raw, false)?;
        let mut row: Record = serde_json::from_str(&raw).map_err(decode)?;
        for &field in &self.times {
            if let Some(encoded) =
                serde_json::from_str::<Option<String>>(row[field].get()).map_err(decode)?
            {
                let bytes = data_encoding::HEXLOWER
                    .decode(encoded.as_bytes())
                    .map_err(|e| sqlx::Error::Decode(e.into()))?;
                let time = event_time::EventTime::decode(&bytes)?.display("+00:00");
                row.insert(field.into(), to_raw_value(&time).map_err(decode)?);
            }
        }
        if self.table == "auth_events" {
            redact(&mut row, key, ids)?;
        }
        Ok(row)
    }
}
fn decode(e: serde_json::Error) -> sqlx::Error {
    sqlx::Error::Decode(e.into())
}

fn redact(row: &mut Record, key: &str, ids: &Identifiers) -> sqlx::Result<()> {
    let mut event = json!({});
    for field in [
        "subject_user_id",
        "subject_identifier",
        "subject_email",
        "subject_format",
        "subject_issuer",
        "actor_user_id",
        "actor_type",
    ] {
        event[field] = serde_json::from_str(row[field].get()).map_err(decode)?;
    }
    if !matches!(
        event["subject_format"].as_str(),
        None | Some("" | "email" | "did" | "opaque" | "iss_sub")
    ) {
        return Err(sqlx::Error::Decode(
            "invalid stored event subject format".into(),
        ));
    }
    let about = is_subject(&event, key, ids);
    let actor = event["actor_user_id"] == key
        || (event["actor_type"] == "user" && event["actor_user_id"].is_null() && about);
    if !about {
        for field in [
            "subject_user_id",
            "subject_identifier",
            "subject_email",
            "subject_issuer",
        ] {
            row.insert(field.into(), RawValue::NULL.to_owned());
        }
    }
    if !actor {
        for field in ["ip_address", "user_agent"] {
            row.insert(field.into(), RawValue::NULL.to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_and_subject_receive_different_parts_of_a_shared_event() {
        let ids = Identifiers::default();
        let key = Uuid::new_v4().to_string();
        let other = Uuid::new_v4().to_string();
        let original = json!({"subject_user_id":key,"subject_format":"email","subject_identifier":null,
            "subject_issuer":null,"subject_email":"member@example.test","actor_user_id":other,"actor_type":"admin",
            "ip_address":"192.0.2.5","user_agent":"operator-client"});
        let mut subject: Record = serde_json::from_value(original.clone()).unwrap();
        redact(&mut subject, &key, &ids).unwrap();
        assert_eq!(subject["ip_address"].get(), "null");
        assert_eq!(subject["user_agent"].get(), "null");
        assert_eq!(subject["subject_email"].get(), r#""member@example.test""#);
        let mut actor: Record = serde_json::from_value(original).unwrap();
        redact(&mut actor, &other, &ids).unwrap();
        assert_eq!(actor["subject_user_id"].get(), "null");
        assert_eq!(actor["subject_email"].get(), "null");
        assert_eq!(actor["ip_address"].get(), r#""192.0.2.5""#);
    }

    #[test]
    fn inventory_excludes_secret_columns_even_when_the_table_is_personal() {
        for (table, fields) in [
            (
                "users",
                &[
                    "password_hash",
                    "totp_secret_encrypted",
                    "encrypted_private_key",
                ][..],
            ),
            ("sessions", &["refresh_token_hash"][..]),
            ("passkey_handles", &["user_handle"][..]),
            (
                "oidc_authorization_codes",
                &["code_hash", "code_challenge", "nonce"][..],
            ),
            ("google_purchases", &["purchase_token"][..]),
            (
                "admin_action_logs",
                &["extra_metadata", "actor_email", "target_id"][..],
            ),
        ] {
            let section = INVENTORY.iter().find(|s| s.table == table).unwrap();
            assert!(
                fields.iter().all(|field| !section.fields.contains(field)),
                "{table}"
            );
        }
    }
}
