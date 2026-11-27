//! Query integers accepted by the REST API.
pub(crate) fn integer(raw: &str) -> Result<String, (&'static str, &'static str)> {
    const INVALID: (&str, &str) = (
        "int_parsing",
        "Input should be a valid integer, unable to parse string as an integer",
    );
    let n = raw.trim();
    let whole = match n.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() && fraction.bytes().all(|b| b == b'0') => {
            whole
        }
        Some(_) => return Err(INVALID),
        None => n,
    };
    let digits = whole.strip_prefix(['-', '+']).unwrap_or(whole);
    if digits.is_empty()
        || !digits
            .split('_')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(INVALID);
    }
    let normalized = digits.replace('_', "");
    let significant = normalized.trim_start_matches('0');
    if significant.len() > 4300 {
        return Err((
            "int_parsing_size",
            "Unable to parse input string as an integer, exceeded maximum size",
        ));
    }
    Ok(whole.replace('_', ""))
}

pub(crate) fn active_only(value: Option<&str>) -> Result<bool, serde_json::Value> {
    match value.map(str::to_ascii_lowercase).as_deref() {
        None | Some("0" | "false" | "no" | "off" | "n" | "f") => Ok(false),
        Some("1" | "true" | "yes" | "on" | "y" | "t") => Ok(true),
        _ => Err(
            serde_json::json!({"type":"bool_parsing","loc":["query","active_only"],"msg":"Input should be a valid boolean, unable to interpret input","input":value}),
        ),
    }
}

fn uuid_reason(path: &str, error: uuid::Error) -> String {
    if path.bytes().all(|c| c.is_ascii_hexdigit()) {
        return format!(
            "invalid length: expected length 32 for simple format, found {}",
            path.len()
        );
    }
    let message = error.to_string();
    if message.starts_with("invalid character:")
        && let Some((prefix, offset)) = message.rsplit_once(" at ")
        && let Ok(index) = offset.parse::<usize>()
    {
        return format!("{prefix} at {}", index + 1);
    }
    message
}

pub(crate) fn path_uuid(path: &str, field: &str) -> Result<uuid::Uuid, serde_json::Value> {
    uuid_field(path, "path", field)
}

pub(crate) fn uuid_field(
    path: &str,
    source: &str,
    field: &str,
) -> Result<uuid::Uuid, serde_json::Value> {
    uuid::Uuid::parse_str(path).map_err(|error| {
        let reason = uuid_reason(path, error);
        serde_json::json!({
            "type":"uuid_parsing", "loc":[source,field],
            "msg":format!("Input should be a valid UUID, {reason}"),
            "input":path, "ctx":{"error":reason}
        })
    })
}

use serde_json::{Value, json};
use std::{borrow::Cow, collections::HashMap};

pub(crate) fn pagination(
    fields: &HashMap<Cow<'_, str>, Cow<'_, str>>,
    default_size: i64,
    max_size: i64,
    issues: &mut Vec<Value>,
) -> (i128, i64) {
    let mut number = |name, default, max| {
        let Some(raw) = fields.get(name) else {
            return default;
        };
        match bounded(name, raw, max) {
            Ok(n) => n,
            Err(e) => {
                issues.push(e);
                default
            }
        }
    };
    (
        number("page", 1, None),
        number("page_size", default_size.into(), Some(max_size.into())) as i64,
    )
}

fn bounded(name: &str, raw: &str, max: Option<i128>) -> Result<i128, Value> {
    let error =
        |kind: &str, msg: &str| json!({"loc":["query",name],"type":kind,"msg":msg,"input":raw});
    let digits = crate::query::integer(raw).map_err(|(k, m)| error(k, m))?;
    let n = digits.parse().unwrap_or_else(|_| {
        if digits.starts_with('-') {
            i128::MIN
        } else {
            i128::MAX
        }
    });
    let (kind, msg, ctx) = if n < 1 {
        (
            "greater_than_equal",
            "Input should be greater than or equal to 1".to_owned(),
            json!({"ge":"1"}),
        )
    } else if let Some(limit) = max.filter(|m| n > *m) {
        (
            "less_than_equal",
            format!("Input should be less than or equal to {limit}"),
            json!({"le":limit.to_string()}),
        )
    } else {
        return Ok(n);
    };
    let mut e = error(kind, &msg);
    e["ctx"] = ctx;
    Err(e)
}
