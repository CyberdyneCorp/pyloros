//! Load the registry fields used by the project overview and member lookup.
use super::*;
use serde_json::value::RawValue;

const COLUMNS: &str = "client_id,name,client_type,active,
    ARRAY_REMOVE(ARRAY[allowed_audiences::text,redirect_uris::text,post_logout_redirect_uris::text],NULL) AS lists,
    ARRAY_REMOVE(ARRAY[timestamptz_send(created_at),timestamptz_send(updated_at),
        timestamptz_send(previous_secret_expires_at),timestamptz_send(last_used_at)],NULL) AS times";

use sqlx::{FromRow, Row, postgres::PgRow};
pub(super) struct Client {
    pub(super) client_id: String,
    pub(super) name: String,
    pub(super) client_type: String,
    pub(super) active: bool,
    lists: Vec<String>,
    times: Vec<Vec<u8>>,
}

impl FromRow<'_, PgRow> for Client {
    fn from_row(row: &PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            client_id: row.try_get("client_id")?,
            name: row.try_get("name")?,
            client_type: row.try_get("client_type")?,
            active: row.try_get("active")?,
            lists: row.try_get("lists")?,
            times: row.try_get("times")?,
        })
    }
}

impl Client {
    fn validate(&self, load_collections: bool) -> sqlx::Result<()> {
        for value in &self.times {
            event_time::EventTime::decode(value)?;
        }
        for list in &self.lists {
            crate::stored_json::check_integers(list)?;
            if load_collections && !valid_collection(list) {
                return Err(sqlx::Error::Decode(
                    "invalid stored client collection".into(),
                ));
            }
        }
        Ok(())
    }
}

fn valid_collection(raw: &str) -> bool {
    match raw.as_bytes().first() {
        Some(b'{' | b'"') => true,
        Some(b'[') => serde_json::from_str::<Vec<&RawValue>>(raw)
            .is_ok_and(|values| values.iter().all(|v| !v.get().starts_with(['[', '{']))),
        _ => raw == "null",
    }
}

pub(super) async fn page(tx: &mut Tx<'_>, page: &Page) -> sqlx::Result<Vec<Client>> {
    let rows: Vec<Client> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM oauth_clients ORDER BY name,client_id LIMIT $1 OFFSET $2"
    ))
    .bind(page.size)
    .bind(page.offset()?)
    .fetch_all(&mut **tx)
    .await?;
    for client in &rows {
        client.validate(false)?;
    }
    Ok(rows)
}

pub(super) async fn exists(tx: &mut Tx<'_>, id: &str) -> sqlx::Result<bool> {
    let row: Option<Client> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM oauth_clients WHERE client_id=$1"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(client) = row {
        client.validate(true)?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_client_collections_accept_scalars_as_members() {
        for allowed in [r#"["a",true,null,3]"#, r#"{"a":[]}"#, r#""ab""#, "null"] {
            assert!(valid_collection(allowed), "{allowed}");
        }
        for invalid in [r#"[["a"]]"#, r#"[{"a":1}]"#, "4"] {
            assert!(!valid_collection(invalid), "{invalid}");
        }
    }
}
