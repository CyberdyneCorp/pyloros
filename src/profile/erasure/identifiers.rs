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
        let identities = sqlx::query_as::<_, (String, String, String, Option<String>)>(
            "SELECT type,provider,identifier,extra_data->>'email' FROM user_identities WHERE user_id=$1"
        )
        .bind(user)
        .fetch_all(&mut **tx)
        .await?;
        for (kind, provider, identifier, extra_email) in identities {
            ids.add(&kind, &provider, Some(&identifier));
            ids.add("email", "", extra_email.as_deref());
        }
        Ok(ids)
    }
    fn add(&mut self, kind: &str, provider: &str, value: Option<&str>) {
        let Some(v) = value.filter(|s| !s.is_empty()) else {
            return;
        };
        match kind {
            "email" | "wallet" | "phone" => {
                let v = v.trim();
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
