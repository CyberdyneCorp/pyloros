//! Query integers accepted by the REST API.
pub(crate) fn integer(raw: &str) -> Result<String, (&'static str, &'static str)> {
    const INVALID: (&str, &str) = (
        "int_parsing",
        "Input should be a valid integer, unable to parse string as an integer",
    );
    // The reference classifies a canonical prefix before normalizing the rest of the text.
    const MAX_SIGNED_WIDTH: usize = 4300;
    if let Some(prefix) = raw.as_bytes().get(..=MAX_SIGNED_WIDTH) {
        let digits = prefix.strip_prefix(b"-").unwrap_or(prefix);
        if matches!(digits[0], b'1'..=b'9') && digits.iter().all(u8::is_ascii_digit) {
            return Err((
                "int_parsing_size",
                "Unable to parse input string as an integer, exceeded maximum size",
            ));
        }
    }
    let n = raw.trim();
    let whole = match n.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() && fraction.bytes().all(|b| b == b'0') => {
            whole
        }
        Some(_) => return Err(INVALID),
        None => n,
    };
    let (negative, digits) = unpad_integer(whole).ok_or(INVALID)?;
    if !digits
        .split('_')
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(INVALID);
    }
    let mut normalized = digits.replace('_', "");
    if negative {
        normalized.insert(0, '-');
    }
    if normalized.len() > MAX_SIGNED_WIDTH {
        return Err(INVALID);
    }
    Ok(normalized)
}

// A zero-padded field can carry its minus sign after the padding. Separators
// in the significant digits still follow the ordinary single-underscore rule.
fn unpad_integer(whole: &str) -> Option<(bool, &str)> {
    let negative = whole.starts_with('-');
    let digits = whole.strip_prefix(['-', '+']).unwrap_or(whole);
    if !digits.starts_with('0') {
        return Some((negative, digits));
    }
    if !digits.as_bytes().last()?.is_ascii_digit() {
        return None;
    }
    let significant = digits.trim_start_matches(['0', '_']);
    if significant.is_empty() {
        return Some((negative, "0"));
    }
    if let Some(rest) = significant.strip_prefix('-') {
        let magnitude = rest.strip_prefix('_').unwrap_or(rest);
        if negative || (magnitude.starts_with('0') && magnitude.len() > 1) {
            return None;
        }
        return Some((true, magnitude));
    }
    Some((negative, significant))
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

fn uuid_reason(path: &str, error: uuid::Error) -> String {
    let (body, offset) = if let Some(body) = path.strip_prefix("urn:uuid:") {
        (body, 9)
    } else if let Some(body) = path.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        (body, 1)
    } else {
        (path, 0)
    };
    if let Some((index, ch)) = body
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_hexdigit() && *ch != '-')
    {
        return format!("invalid character: found `{ch}` at {}", offset + index + 1);
    }
    let groups = body.split('-');
    let count = groups.clone().count();
    if offset == 0 && count == 1 {
        return format!(
            "invalid length: expected length 32 for simple format, found {}",
            body.len()
        );
    }
    if count != 5 {
        return format!("invalid group count: expected 5, found {count}");
    }
    for (index, (group, expected)) in groups.zip([8, 4, 4, 4, 12]).enumerate() {
        if group.len() != expected {
            // The last-group diagnostic includes the submitted wrapper.
            let found = group.len()
                + if index == 4 {
                    path.len() - body.len()
                } else {
                    0
                };
            return format!(
                "invalid group length in group {index}: expected {expected}, found {found}"
            );
        }
    }
    error.to_string()
}

/// UUID text in stored cursors and signed billing references uses legacy integer syntax.
pub(crate) fn legacy_uuid(value: &str) -> Option<uuid::Uuid> {
    let hex = value.replace("urn:", "").replace("uuid:", "");
    let hex = hex.trim_matches(['{', '}']).replace('-', "");
    if hex.chars().count() != 32 {
        return None;
    }
    let digits = crate::unicode_decimal::hexadecimal_magnitude(&hex)?;
    u128::from_str_radix(&digits, 16)
        .ok()
        .map(uuid::Uuid::from_u128)
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
mod integer_tests {
    use super::integer;

    #[test]
    fn zero_padding_is_normalized_before_integer_bounds() {
        for (text, expected) in [
            ("0__2", 2),
            ("-00___2", -2),
            ("+0_0__2.0", 2),
            ("0_-1", -1),
            ("0-_2", -2),
            ("0__0", 0),
            ("0-1_2", -12),
        ] {
            assert_eq!(
                integer(text).map(|s| s.parse::<i32>().unwrap()),
                Ok(expected),
                "{text}"
            );
        }
        for text in ["1__2", "0_.0", "-0-1", "0-01", "0--2", "0-__2", "0+2"] {
            assert!(integer(text).is_err(), "{text}");
        }
    }

    #[test]
    fn wide_signed_text_preserves_the_issue_type_before_bounds_checks() {
        let digits = "8".repeat(4300);
        assert!(integer(&digits).is_ok());
        assert!(integer(&format!("-{}", &digits[..4299])).is_ok());
        for source in [
            format!("-{digits}"),
            format!("{digits}1x"),
            format!("{digits}1.0"),
        ] {
            assert_eq!(integer(&source).unwrap_err().0, "int_parsing_size");
        }
        for source in [
            format!("+{digits}1"),
            format!("-0{digits}"),
            format!("{digits}_1"),
        ] {
            assert_eq!(integer(&source).unwrap_err().0, "int_parsing");
        }
    }
}

#[cfg(test)]
mod uuid_tests {
    use super::*;

    #[test]
    fn historical_payment_references_resolve_to_the_same_account() {
        let compact = "12ab".repeat(8);
        let account = uuid::Uuid::parse_str(&compact).unwrap();
        for reference in [
            account.to_string(),
            compact.to_uppercase(),
            format!("{{{compact}}}"),
            format!("{}-{}", &compact[..7], &compact[7..]),
            format!("urn:uuid:{compact}"),
            compact.replace('2', "٢"),
        ] {
            assert_eq!(super::legacy_uuid(&reference), Some(account));
        }
        for reference in [
            format!("URN:UUID:{account}"),
            compact[..31].to_owned(),
            format!("{}G", &compact[..31]),
        ] {
            assert_eq!(super::legacy_uuid(&reference), None);
        }
    }

    #[test]
    fn long_uuid_fields_report_character_and_group_errors() {
        for (input, reason) in [
            ("٠".repeat(32), "invalid character: found `٠` at 1"),
            (
                format!("urn:uuid:{{{}}}", uuid::Uuid::nil()),
                "invalid character: found `{` at 10",
            ),
            ("-".repeat(60), "invalid group count: expected 5, found 61"),
            (
                format!("{}-b-c-d-e", "a".repeat(50)),
                "invalid group length in group 0: expected 8, found 50",
            ),
        ] {
            let error = uuid_field(&input, "query", "organization_id").unwrap_err();
            assert_eq!(error["ctx"]["error"], reason);
        }
    }

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
