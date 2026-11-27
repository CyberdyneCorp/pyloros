use super::*;
use serde_json::Map;
use std::{borrow::Cow, collections::HashMap};

pub(super) struct Filters {
    pub audit: Map<String, Value>,
    pub start: Option<datetime::ParsedDateTime>,
    pub end: Option<datetime::ParsedDateTime>,
    pub cursor: Option<String>,
    pub user: Option<Uuid>,
    pub actor: Option<Uuid>,
    pub limit: i64,
}

struct Params<'a> {
    values: HashMap<Cow<'a, str>, Cow<'a, str>>,
    issues: Vec<Value>,
}

impl Params<'_> {
    fn text(&mut self, key: &str, max: usize) -> Option<String> {
        let v = self.values.get(key)?;
        if v.chars().count() > max {
            self.issues.push(json!({"type":"string_too_long","loc":["query",key],"msg":format!("String should have at most {max} characters"),"input":v,"ctx":{"max_length":max.to_string()}}));
        }
        Some(v.to_string())
    }
    fn id(&mut self, key: &str) -> Option<Uuid> {
        let v = self.values.get(key)?;
        crate::query::uuid_field(v, "query", key)
            .map_err(|e| self.issues.push(e))
            .ok()
    }
    fn choice(&mut self, key: &str, allowed: &[&str]) -> Option<String> {
        let val = self.values.get(key)?;
        if !allowed.contains(&val.as_ref()) {
            let (last, rest) = allowed.split_last().expect("enumerated values");
            let choices = rest
                .iter()
                .map(|s| format!("'{s}'"))
                .collect::<Vec<_>>()
                .join(", ");
            let expected = format!("{choices} or '{last}'");
            self.issues.push(json!({"type":"enum","loc":["query",key],"input":val,"msg":format!("Input should be {expected}"),"ctx":{"expected":expected}}));
        }
        Some(val.to_string())
    }
    fn date(&mut self, key: &str) -> Option<datetime::ParsedDateTime> {
        let input = json!(self.values.get(key)?);
        datetime::parse_utc(&input)
            .map_err(|mut e| {
                e["loc"] = json!(["query", key]);
                e["input"] = input;
                self.issues.push(e)
            })
            .ok()
    }
}

impl Filters {
    pub(super) fn parse(path: Option<&str>, raw: &str) -> Result<Self, Vec<Value>> {
        let mut p = Params {
            values: url::form_urlencoded::parse(raw.as_bytes()).collect(),
            issues: Vec::new(),
        };
        let mut f = Self {
            audit: Map::new(),
            start: None,
            end: None,
            cursor: None,
            user: None,
            actor: None,
            limit: if path.is_some() { 20 } else { 50 },
        };
        if let Some(path) = path {
            f.user = crate::query::path_uuid(path, "user_id")
                .map_err(|e| p.issues.push(e))
                .ok();
        } else {
            f.global(&mut p);
        }
        if let Some(id) = f.user {
            f.audit.insert("subject_user_id".into(), json!(id));
        }
        f.cursor = p.text("cursor", 256);
        if let Some(v) = p.values.get("limit") {
            match crate::query::bounded("limit", v, Some(200)) {
                Ok(n) => f.limit = n as i64,
                Err(e) => p.issues.push(e),
            }
        }
        if p.issues.is_empty() {
            Ok(f)
        } else {
            Err(p.issues)
        }
    }

    fn global(&mut self, p: &mut Params<'_>) {
        self.filter("subject_email", p.text("subject_email", 320));
        self.user = p.id("subject_user_id");
        self.filter("client_id", p.text("client_id", 128));
        self.filter("outcome", p.choice("outcome", catalog::OUTCOMES));
        if p.values.contains_key("activity") {
            let activities: Vec<_> = catalog::CLASSES
                .iter()
                .flat_map(|(_, v)| v.iter().copied())
                .collect();
            self.filter("activity", p.choice("activity", &activities));
        }
        self.filter("reason_code", p.choice("reason_code", catalog::REASONS));
        self.actor = p.id("actor_user_id");
        if let Some(id) = self.actor {
            self.audit.insert("actor_user_id".into(), json!(id));
        }
        self.start = p.date("from");
        self.end = p.date("to");
        self.filter("from", self.start.as_ref().map(|d| d.audit_time()));
        self.filter("to", self.end.as_ref().map(|d| d.audit_time()));
    }
    fn filter(&mut self, k: &str, v: Option<String>) {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            self.audit.insert(k.into(), json!(v));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_already_enabled_mfa_as_a_reason_filter() {
        let filters = Filters::parse(None, "reason_code=mfa_already_enabled").unwrap();
        assert_eq!(filters.audit["reason_code"], "mfa_already_enabled");
    }

    #[test]
    fn reports_invalid_global_filters_in_contract_order() {
        let issues = Filters::parse(None, "limit=0&outcome=invalid&reason_code=invalid")
            .err()
            .unwrap();
        let fields: Vec<_> = issues
            .iter()
            .map(|issue| issue["loc"][1].as_str().unwrap())
            .collect();
        assert_eq!(fields, ["outcome", "reason_code", "limit"]);
    }
}
