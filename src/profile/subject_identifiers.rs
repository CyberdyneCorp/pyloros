use super::*;
use std::collections::BTreeSet;

#[derive(Default)]
pub(super) struct Identifiers {
    pub(super) emails: BTreeSet<String>,
    pub(super) wallets: BTreeSet<String>,
    pub(super) phones: BTreeSet<String>,
    pub(super) social: BTreeSet<(String, String)>,
}
impl Identifiers {
    pub(super) async fn collect(
        tx: &mut Transaction<'_, Postgres>,
        user: Uuid,
        email: Option<&str>,
        phone: Option<&str>,
        wallet: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        let mut ids = Self::default();
        ids.add("email", "", email);
        ids.add("phone", "", phone);
        ids.add("wallet", "", wallet);
        let identities = sqlx::query_as::<_, (String, String, String, String, Vec<u8>)>(
            "SELECT type,provider,identifier,extra_data::text,timestamptz_send(created_at) FROM user_identities WHERE user_id=$1"
        )
        .bind(user)
        .fetch_all(&mut **tx)
        .await?;
        for (kind, provider, identifier, metadata, created) in identities {
            ids.add(&kind, &provider, Some(&identifier));
            event_time::EventTime::decode(&created)?;
            ids.add("email", "", identity_email(&metadata)?.as_deref());
        }
        Ok(ids)
    }
    fn add(&mut self, kind: &str, provider: &str, value: Option<&str>) {
        let Some(v) = value.filter(|s| !s.is_empty()) else {
            return;
        };
        match kind {
            "email" | "wallet" | "phone" => {
                let v = admin_fields::trimmed(v);
                if v.is_empty() {
                    return;
                }
                match kind {
                    "email" => self.emails.insert(v.to_lowercase()),
                    "wallet" => self.wallets.insert(v.to_lowercase()),
                    _ => self.phones.insert(v.to_owned()),
                };
            }
            _ => {
                self.social.insert((provider.to_owned(), v.to_owned()));
            }
        }
    }
    pub(super) fn needles(&self) -> Vec<String> {
        self.emails
            .iter()
            .chain(&self.wallets)
            .chain(&self.phones)
            .chain(self.social.iter().map(|(_, id)| id))
            .map(|v| v.to_lowercase())
            .collect()
    }
}

pub(super) fn is_subject(event: &Value, key: &str, ids: &Identifiers) -> bool {
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

fn identity_email(raw: &str) -> sqlx::Result<Option<String>> {
    use serde_json::value::RawValue;
    use std::collections::BTreeMap;
    let invalid = || sqlx::Error::Decode("invalid stored identity metadata".into());
    let normalized = admin_organizations::normalized_storage(raw)?;
    let fields: BTreeMap<String, &RawValue> =
        serde_json::from_str(normalized.as_deref().unwrap_or(raw)).map_err(|_| invalid())?;
    let Some(value) = fields.get("email").map(|v| v.get()) else {
        return Ok(None);
    };
    if value.starts_with('"') {
        return serde_json::from_str(value).map(Some).map_err(|_| invalid());
    }
    if matches!(value, "null" | "false" | "[]" | "{}") || value.parse::<f64>() == Ok(0.0) {
        return Ok(None);
    }
    Err(invalid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_email_preserves_text_and_extracts_the_last_historical_pair() {
        assert_eq!(
            identity_email(r#"[["email","a"],["email"," B "]]"#)
                .unwrap()
                .as_deref(),
            Some(" B ")
        );
        for value in ["0", "false", "[]", "{}", "null"] {
            assert_eq!(
                identity_email(&format!("{{\"email\":{value}}}")).unwrap(),
                None
            );
        }
        for raw in [r#"{"email":7}"#, r#"{"email":[1]}"#, "true", "[42]"] {
            assert!(identity_email(raw).is_err(), "{raw}");
        }
    }
}
