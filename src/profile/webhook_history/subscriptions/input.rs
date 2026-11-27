use super::*;
use admin_fields::Fields;

const EVENTS: [&str; 5] = [
    "role.granted",
    "role.revoked",
    "user.deleted",
    "user.registered",
    "webhook.test",
];

#[derive(Debug)]
pub(super) struct Input {
    pub name: Option<String>,
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub active: Option<bool>,
    pub description: Option<String>,
    pub changed: Vec<&'static str>,
}

pub(super) fn parse(value: &Value, create: bool) -> Result<Input, Vec<Value>> {
    let body = admin_fields::object(value)?;
    let mut fields = Fields {
        body,
        issues: vec![],
    };
    let name = text(&mut fields, "name", 100, create);
    let url = text(&mut fields, "url", 2048, create);
    let events = events(&mut fields, create);
    let active = body
        .get("is_active")
        .filter(|v| create || !v.is_null())
        .map(|_| fields.boolean("is_active"));
    let description = fields.string("description", Some(1000), false);
    let changed = ["description", "event_types", "is_active", "name", "url"]
        .into_iter()
        .filter(|k| body.contains_key(*k))
        .collect();
    if fields.issues.is_empty() {
        Ok(Input {
            name,
            url,
            events,
            active,
            description,
            changed,
        })
    } else {
        Err(fields.issues)
    }
}

fn text(fields: &mut Fields<'_>, key: &str, max: usize, required: bool) -> Option<String> {
    let present = fields.body.get(key).is_some_and(|v| !v.is_null());
    fields.string(key, Some(max), required || present)
}

fn events(fields: &mut Fields<'_>, create: bool) -> Option<Vec<String>> {
    let key = "event_types";
    let Some(raw) = fields.body.get(key) else {
        if create {
            fields.issues.push(json!({"loc":["body",key],"type":"missing","msg":"Field required","input":fields.body}));
        }
        return None;
    };
    if let Some(items) = raw.as_array() {
        let n = items.len();
        if n > 16 || (create && n == 0) {
            let (kind, constraint, limit, msg) = if n == 0 {
                ("too_short", "min_length", "1", "at least 1 item")
            } else {
                ("too_long", "max_length", "16", "at most 16 items")
            };
            fields.issues.push(json!({"type":kind,"loc":["body",key],"msg":format!("List should have {msg} after validation, not {n}"),"input":raw,"ctx":{"field_type":"List",constraint:limit,"actual_length":n.to_string()}}));
            return None;
        }
    }
    let start = fields.issues.len();
    let mut values = fields.string_list(key, !create)?;
    if start == fields.issues.len()
        && (values.is_empty() || values.iter().any(|v| !EVENTS.contains(&v.as_str())))
    {
        let reason = format!(
            "event_types must be a non-empty subset of ['{}']",
            EVENTS.join("', '")
        );
        fields.issues.push(json!({"type":"value_error","loc":["body",key],"msg":format!("Value error, {reason}"),"input":raw,"ctx":{"error":reason}}));
    }
    values.sort();
    values.dedup();
    Some(values)
}
