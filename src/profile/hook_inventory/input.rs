//! Validate v1 authoring fields in schema order and retain raw inputs for diagnostics.
use super::*;
use crate::request_json::{fields, token_field};
use serde_json::value::RawValue;

const KEYS: &[&str] = &[
    "name",
    "event_type",
    "code",
    "is_active",
    "timeout_seconds",
    "allow_network",
    "receive_pii",
];
const EVENTS: &[&str] = &[
    "entitlement_granted",
    "entitlement_revoked",
    "role_granted",
    "role_revoked",
    "user_deleted",
    "user_logged_in",
    "user_registered",
];

pub(super) fn parse(
    raw: &RawValue,
    path: Option<&str>,
) -> Result<(Option<Uuid>, Value), Box<Response>> {
    let submitted = fields::object_fields(raw)?;
    let body = fields::project_scalars(raw, &submitted, KEYS);
    let mut issues = Vec::new();
    let path_input = serde_json::value::to_raw_value(&path).expect("string path");
    let id = path.and_then(|s| {
        crate::query::path_uuid(s, "hook_id")
            .map_err(|issue| issues.push((issue, &*path_input)))
            .ok()
    });
    let output = match admin_fields::object_field(&body) {
        Ok(_) => parse_fields(&body, &submitted, raw, path.is_some(), &mut issues),
        Err(issue) => {
            issues.push((issue, raw));
            Value::Null
        }
    };
    if issues.is_empty() {
        Ok((id, output))
    } else {
        Err(fields::invalid(issues))
    }
}

fn parse_fields<'a>(
    body: &Value,
    submitted: &HashMap<String, &'a RawValue>,
    raw: &'a RawValue,
    editing: bool,
    issues: &mut Vec<(Value, &'a RawValue)>,
) -> Value {
    let mut output = json!({});
    for &key in KEYS {
        let original = submitted.get(key).copied();
        if editing && original.is_none_or(|v| v.get() == "null") {
            continue;
        }
        if original.is_none() && !matches!(key, "name" | "event_type" | "code") {
            continue;
        }
        match field(body, key, original) {
            Ok(value) => output[key] = value,
            Err(issue) => issues.push((issue, original.unwrap_or(raw))),
        }
    }
    output
}

fn field(body: &Value, key: &str, raw: Option<&RawValue>) -> Result<Value, Value> {
    match key {
        "name" | "code" => token_field(
            body.clone(),
            key,
            1,
            if key == "code" { 10_000 } else { 100 },
        )
        .map(Value::String),
        "event_type" => {
            let event = token_field(body.clone(), key, 0, usize::MAX)?;
            if EVENTS.contains(&event.as_str()) {
                return Ok(json!(event));
            }
            let reason = format!("event_type must be one of ['{}']", EVENTS.join("', '"));
            Err(
                json!({"loc":["body",key],"type":"value_error","msg":format!("Value error, {reason}"),"ctx":{"error":reason}}),
            )
        }
        "timeout_seconds" => timeout(raw.expect("present timeout")),
        _ => {
            let mut form = admin_fields::Fields {
                body: body.as_object().expect("validated object"),
                issues: Vec::new(),
            };
            let value = form.boolean(key);
            form.issues.pop().map_or(Ok(json!(value)), Err)
        }
    }
}

fn timeout(raw: &RawValue) -> Result<Value, Value> {
    let issue =
        |kind: &str, msg: &str| json!({"loc":["body","timeout_seconds"],"type":kind,"msg":msg});
    let digits = fields::integer_text(raw).map_err(|(kind, msg)| issue(kind, msg))?;
    if let Ok(n @ 1..=30) = digits.parse::<i32>() {
        return Ok(json!(n));
    }
    let (mut error, ctx) = if digits == "0" || digits.starts_with('-') {
        (
            issue(
                "greater_than_equal",
                "Input should be greater than or equal to 1",
            ),
            json!({"ge":"1"}),
        )
    } else {
        (
            issue(
                "less_than_equal",
                "Input should be less than or equal to 30",
            ),
            json!({"le":"30"}),
        )
    };
    error["ctx"] = ctx;
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn invalid_identifier_and_settings_preserve_order_and_submitted_values() {
        let raw = RawValue::from_string(
            r#"{"name":"","timeout_seconds":123456789012345678901,"receive_pii":[true]}"#.into(),
        )
        .unwrap();
        let response = parse(&raw, Some("validate")).unwrap_err();
        let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
        let wire = std::str::from_utf8(&bytes).unwrap();
        assert!(wire.contains("123456789012345678901"));
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let detail = body["detail"].as_array().unwrap();
        let fields: Vec<_> = detail
            .iter()
            .map(|e| e["loc"][1].as_str().unwrap())
            .collect();
        assert_eq!(
            fields,
            ["hook_id", "name", "timeout_seconds", "receive_pii"]
        );
        assert_eq!(detail[3]["input"], json!([true]));
    }
}
