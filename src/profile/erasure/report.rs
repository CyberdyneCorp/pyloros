use super::*;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Deserialize, Serialize)]
struct Processor {
    name: String,
    holds: String,
    action: String,
    reached: bool,
}

#[derive(Deserialize)]
pub(in crate::profile) struct Settings {
    retained: BTreeMap<String, String>,
    processors: Vec<Processor>,
    #[serde(skip)]
    enabled: Vec<&'static str>,
}

impl Settings {
    pub(in crate::profile) fn configured() -> Result<Self, Box<dyn Error>> {
        let text = match env::var_os("PYLOROS_ERASURE_REPORT_PATH") {
            Some(path) => std::fs::read_to_string(path)?,
            None => include_str!("report.json").to_owned(),
        };
        let mut settings: Self = serde_json::from_str(&text)?;
        for table in [
            "admin_action_logs",
            "webhook_events",
            "oauth_token_issuance_log",
        ] {
            if !settings.retained.contains_key(table) {
                return Err(format!("missing retained table {table}").into());
            }
        }
        for name in [
            "Stripe",
            "Apple App Store",
            "Google Play",
            "Email delivery provider",
            "Sentry",
            "Public blockchain",
            "Relying parties",
        ] {
            if settings
                .processors
                .iter()
                .filter(|p| p.name == name)
                .count()
                != 1
            {
                return Err(format!("expected one report entry for {name}").into());
            }
        }
        for (name, enabled) in [
            (
                "Email delivery provider",
                env::var("EMAIL_PROVIDER").is_ok_and(|v| v != "mock"),
            ),
            ("Sentry", env::var_os("SENTRY_DSN").is_some()),
            (
                "Public blockchain",
                config::flag_with_default("BLOCKCHAIN_ENABLED", false)?,
            ),
            (
                "Relying parties",
                config::flag_with_default("WEBHOOKS_ENABLED", true)?,
            ),
        ] {
            if enabled {
                settings.enabled.push(name);
            }
        }
        Ok(settings)
    }

    pub(super) fn render(&self, counts: &Counts) -> Value {
        let billing = [
            ("stripe_customers", "Stripe"),
            ("apple_transactions", "Apple App Store"),
            ("google_purchases", "Google Play"),
        ];
        let names = billing
            .iter()
            .filter(|(t, _)| counts.deleted.contains_key(*t))
            .map(|(_, p)| *p)
            .chain(self.enabled.iter().copied());
        let processors: Vec<_> = names
            .filter_map(|name| self.processors.iter().find(|p| p.name == name))
            .collect();
        json!({"deleted":counts.deleted,"pseudonymised":counts.rewritten,"retained":self.retained,"processors":processors})
    }
    pub(super) fn totals(&self, counts: &Counts, sessions: u64) -> Value {
        json!({"rows_deleted":counts.deleted.values().sum::<i64>(),
            "rows_pseudonymised":counts.rewritten.values().sum::<i64>(),
            "sessions_revoked":sessions,"retained":self.retained.keys().collect::<Vec<_>>()})
    }
}
#[derive(Default)]
pub(super) struct Counts {
    pub(super) deleted: BTreeMap<&'static str, i64>,
    pub(super) rewritten: BTreeMap<&'static str, i64>,
}

impl Counts {
    pub(super) fn deleted(&mut self, table: &'static str, count: i64) {
        if count > 0 {
            self.deleted.insert(table, count);
        }
    }
    pub(super) fn rewritten(&mut self, table: &'static str, count: i64) {
        if count > 0 {
            self.rewritten.insert(table, count);
        }
    }
}
