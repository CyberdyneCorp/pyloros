use super::*;
use crate::profile::subject_identifiers::{Identifiers, is_subject};
use serde_json::value::{RawValue, to_raw_value};
use std::collections::BTreeMap;
use std::sync::LazyLock;

#[derive(Deserialize)]
struct Entry {
    table: &'static str,
    strategy: &'static str,
    #[serde(default)]
    optional: bool,
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
        if let Some(section) = entry.section(tx, settings, user, ids, since).await? {
            result.push(section);
        }
    }
    Ok(result)
}

impl Entry {
    async fn section(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        settings: &erasure::Settings,
        user: Uuid,
        ids: &Identifiers,
        since: DateTime<Utc>,
    ) -> sqlx::Result<Option<Section>> {
        if self.optional {
            let installed: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
                .bind(self.table)
                .fetch_one(&mut **tx)
                .await?;
            if !installed {
                return Ok(None);
            }
        }
        let mut note = settings.export_note(self.table).map(str::to_owned);
        let mut rows = self.read(tx, user, ids, since).await?;
        if self.optional && rows.is_empty() {
            return Ok(None);
        }
        if self.table == "auth_events" {
            note = Some(format!(
                "Events since {}, newest first. {}",
                since.date_naive(),
                note.unwrap_or_default()
            ));
        }
        let truncated = rows.len() > 1000;
        rows.truncate(1000);
        Ok(Some(Section {
            table: self.table,
            on_erasure: self.strategy,
            rows,
            truncated,
            note,
        }))
    }
    async fn read(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user: Uuid,
        ids: &Identifiers,
        since: DateTime<Utc>,
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
        let select = |predicate: &str| {
            format!(
                "SELECT row_to_json(r)::text FROM (SELECT {projection} FROM {} WHERE {predicate} LIMIT 1001) r",
                self.table
            )
        };
        let sql;
        let query = match self.table {
            "webhook_events" | "oauth_token_issuance_log" => return Ok(Vec::new()),
            "phone_otps" if ids.phones.is_empty() => return Ok(Vec::new()),
            "phone_otps" => {
                sql = select("phone_number=ANY($1)");
                sqlx::query_scalar(&sql).bind(ids.phones.iter().collect::<Vec<_>>())
            }
            "auth_challenges" => {
                sql = select("user_id=$1 OR lower(wallet_address)=ANY($2)");
                sqlx::query_scalar(&sql)
                    .bind(user)
                    .bind(ids.wallets.iter().collect::<Vec<_>>())
            }
            "iam_identities" => {
                sql = select("user_id=$1 OR lower(email)=ANY($2) OR lower(owner_address)=ANY($3)");
                sqlx::query_scalar(&sql)
                    .bind(user)
                    .bind(ids.emails.iter().collect::<Vec<_>>())
                    .bind(ids.wallets.iter().collect::<Vec<_>>())
            }
            "auth_events" => {
                sql = select("(subject_user_id=$1 OR actor_user_id=$1 OR lower(subject_email)=ANY($2)
                    OR subject_identifier=ANY($3) OR subject_identifier LIKE ANY($4)) AND occurred_at>=$5 ORDER BY occurred_at DESC");
                sqlx::query_scalar(&sql)
                    .bind(user)
                    .bind(ids.emails.iter().collect::<Vec<_>>())
                    .bind(
                        ids.social
                            .iter()
                            .map(|(_, subject)| subject)
                            .collect::<Vec<_>>(),
                    )
                    .bind(
                        ids.wallets
                            .iter()
                            .map(|wallet| format!("did:pkh:eip155:%:{wallet}"))
                            .collect::<Vec<_>>(),
                    )
                    .bind(since)
            }
            table => {
                sql = select(match table {
                    "users" => "id=$1",
                    "admin_action_logs" => "actor_user_id=$1",
                    "pyloros_user_relationships" => {
                        "user_id=$1 ORDER BY client_id,object_type,object_id,relation"
                    }
                    _ => "user_id=$1",
                });
                sqlx::query_scalar(&sql).bind(user)
            }
        };
        let raw: Vec<String> = query.fetch_all(&mut **tx).await?;
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

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn optional_graph_section_only_exports_the_subjects_assignments() -> sqlx::Result<()> {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL search_path TO pg_temp")
            .execute(&mut *tx)
            .await?;
        let entry = INVENTORY
            .iter()
            .find(|e| e.table == "pyloros_user_relationships")
            .unwrap();
        let settings = serde_json::from_value(json!({"retained":{}, "processors":[]})).unwrap();
        let ids = Identifiers::default();
        let user = Uuid::new_v4();
        let now = Utc::now();
        assert!(
            entry
                .section(&mut tx, &settings, user, &ids, now)
                .await?
                .is_none()
        );
        sqlx::raw_sql("CREATE TEMP TABLE pyloros_user_relationships (
            client_id uuid, object_type text, object_id text, relation text, user_id uuid
        ); INSERT INTO pyloros_user_relationships VALUES (gen_random_uuid(),'file','foreign','viewer',gen_random_uuid());")
            .execute(&mut *tx).await?;
        assert!(
            entry
                .section(&mut tx, &settings, user, &ids, now)
                .await?
                .is_none()
        );
        sqlx::query(
            "INSERT INTO pyloros_user_relationships
            SELECT $1,'file',lpad(n::text,4,'0'),'viewer',$2 FROM generate_series(1001,1,-1) n",
        )
        .bind(Uuid::new_v4())
        .bind(user)
        .execute(&mut *tx)
        .await?;
        let section = entry
            .section(&mut tx, &settings, user, &ids, now)
            .await?
            .unwrap();
        assert!(section.truncated);
        assert_eq!(section.rows.len(), 1000);
        assert_eq!(section.rows[0]["object_id"].get(), r#""0001""#);
        assert_eq!(section.rows[999]["object_id"].get(), r#""1000""#);
        tx.rollback().await
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
