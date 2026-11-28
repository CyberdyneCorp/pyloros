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
    boolean("active_only", value.unwrap_or("false"))
}

pub(crate) fn boolean(name: &str, value: &str) -> Result<bool, serde_json::Value> {
    match value.to_ascii_lowercase().as_str() {
        "0" | "false" | "no" | "off" | "n" | "f" => Ok(false),
        "1" | "true" | "yes" | "on" | "y" | "t" => Ok(true),
        _ => Err(
            serde_json::json!({"type":"bool_parsing","loc":["query",name],"msg":"Input should be a valid boolean, unable to interpret input","input":value}),
        ),
    }
}

// The REST diagnostic includes wrapping braces or the URN prefix in the final length.
fn invalid_final_uuid_group(path: &str) -> Option<usize> {
    let body = path
        .strip_prefix("urn:uuid:")
        .or_else(|| path.strip_prefix('{')?.strip_suffix('}'))
        .unwrap_or(path);
    let mut groups = body.splitn(5, '-');
    for width in [8, 4, 4, 4] {
        let group = groups.next()?;
        if group.len() != width || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
    }
    let last = groups.next()?;
    (last.len() != 12 && last.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| last.len() + (path.len() - body.len()))
}

fn uuid_reason(path: &str, error: uuid::Error) -> String {
    if path.bytes().all(|c| c.is_ascii_hexdigit()) {
        return format!(
            "invalid length: expected length 32 for simple format, found {}",
            path.len()
        );
    }
    if let Some(length) = invalid_final_uuid_group(path) {
        return format!("invalid group length in group 4: expected 12, found {length}");
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
    const URN: &str = "urn:uuid:";
    let parsed = match path.get(..URN.len()) {
        Some(prefix) if prefix != URN && prefix.eq_ignore_ascii_case(URN) => {
            let first = char::from(prefix.as_bytes()[0]);
            Err(format!("invalid character: found `{first}` at 1"))
        }
        _ => uuid::Uuid::parse_str(path).map_err(|error| uuid_reason(path, error)),
    };
    parsed.map_err(|reason| {
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

pub(crate) fn bounded(name: &str, raw: &str, max: Option<i128>) -> Result<i128, Value> {
    range(name, raw, 1, max)
}

pub(crate) fn range(name: &str, raw: &str, min: i128, max: Option<i128>) -> Result<i128, Value> {
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
    let (kind, msg, ctx) = if n < min {
        (
            "greater_than_equal",
            format!("Input should be greater than or equal to {min}"),
            json!({"ge":min.to_string()}),
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

#[cfg(test)]
mod uuid_tests {
    use super::*;

    #[test]
    fn final_uuid_group_length_includes_the_submitted_wrapper() {
        let short = "00000000-0000-0000-0000-00000000000";
        for (value, count) in [
            (short.to_owned(), 11),
            (format!("{{{short}}}"), 13),
            (format!("urn:uuid:{short}"), 20),
            (format!("urn:uuid:{short}00"), 22),
        ] {
            let error = path_uuid(&value, "user_id").unwrap_err();
            assert_eq!(
                error["ctx"]["error"],
                format!("invalid group length in group 4: expected 12, found {count}")
            );
        }
    }

    #[test]
    fn typed_uuid_fields_require_a_lowercase_urn_prefix() {
        let id = uuid::Uuid::from_u128(0xabcdef);
        let suffix = id.to_string().to_ascii_uppercase();
        for source in ["path", "query", "body"] {
            assert_eq!(
                uuid_field(&format!("urn:uuid:{suffix}"), source, "user_id").unwrap(),
                id
            );
            for prefix in ["URN:UUID:", "Urn:uuid:", "urn:UUID:"] {
                let value = format!("{prefix}{suffix}");
                let error = uuid_field(&value, source, "user_id").unwrap_err();
                let first = prefix.chars().next().unwrap();
                assert_eq!(
                    error["ctx"]["error"],
                    format!("invalid character: found `{first}` at 1")
                );
                assert_eq!(error["loc"], json!([source, "user_id"]));
                assert_eq!(error["input"], value);
            }
        }
    }
}
