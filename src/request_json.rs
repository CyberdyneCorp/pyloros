pub(crate) mod encoding;
pub(crate) mod fields;
pub(crate) mod iam_document;
use crate::token_http::header;
use axum::http::HeaderMap;
use serde_json::{Value, json};

pub(crate) fn is_json(headers: &HeaderMap) -> bool {
    let mime = header(headers, "content-type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime.strip_prefix("application/")
        .is_some_and(|s| s == "json" || s.ends_with("+json"))
}

pub(crate) fn parse_body(headers: &HeaderMap, bytes: &[u8]) -> Result<Value, Value> {
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    if !is_json(headers) {
        return Ok(Value::String(String::from_utf8_lossy(bytes).into_owned()));
    }
    serde_json::from_slice(bytes).map_err(|error| json_issue(bytes, error))
}

pub(crate) fn json_issue(bytes: &[u8], error: serde_json::Error) -> Value {
    let text = String::from_utf8_lossy(bytes);
    let start: usize = text
        .split_inclusive('\n')
        .take(error.line().saturating_sub(1))
        .map(str::len)
        .sum();
    let end = if error.is_eof() {
        bytes.len()
    } else {
        start + error.column().saturating_sub(1)
    };
    let prefix = String::from_utf8_lossy(&bytes[..end.min(bytes.len())]);
    let diagnostic = error.to_string();
    let reason = diagnostic
        .rsplit_once(" at line ")
        .map_or(diagnostic.as_str(), |(reason, _)| reason);
    let message = match reason {
        "key must be a string" => "Expecting property name enclosed in double quotes",
        "expected value" | "EOF while parsing a value" => "Expecting value",
        "expected colon" => "Expecting ':' delimiter",
        "trailing characters" => "Extra data",
        "EOF while parsing an object" if prefix.trim_end().ends_with(['{', ',']) => {
            "Expecting property name enclosed in double quotes"
        }
        "expected `,` or `}`" | "expected `,` or `]`" | "EOF while parsing an object" => {
            "Expecting ',' delimiter"
        }
        other => other,
    };
    let (offset, message) = syntax_location(&text, end, reason, message);
    json!({"loc":["body",offset],"type":"json_invalid","msg":"JSON decode error","input":{},"ctx":{"error":message}})
}

fn syntax_location<'a>(text: &str, end: usize, reason: &str, default: &'a str) -> (usize, &'a str) {
    let prefix = &text[..text.floor_char_boundary(end)];
    let string_error = matches!(reason, "EOF while parsing a string" | "invalid escape")
        || reason.starts_with("control character")
        || reason.contains("hex code");
    if string_error && let Some(issue) = string_diagnostic(text) {
        return issue;
    }
    if matches!(reason, "expected ident" | "EOF while parsing a value") {
        let start = prefix.trim_end_matches(|c: char| c.is_ascii_alphabetic());
        let literal = &prefix[start.len()..];
        if !literal.is_empty()
            && ["true", "false", "null"]
                .iter()
                .any(|s| s.starts_with(literal))
        {
            return (start.chars().count(), "Expecting value");
        }
    }
    if let Some(before) = prefix
        .trim_end_matches([' ', '\n', '\t', '\r'])
        .strip_suffix(',')
    {
        let message = match text.as_bytes().get(end) {
            Some(b'}') => Some("Illegal trailing comma before end of object"),
            Some(b']') => Some("Illegal trailing comma before end of array"),
            _ => None,
        };
        if let Some(message) = message {
            return (before.chars().count(), message);
        }
    }
    (prefix.chars().count(), default)
}

// The wire error identifies the opening quote or escape, while the decoder can
// stop at the later character that made it invalid. Offsets count Unicode scalars.
fn string_diagnostic(text: &str) -> Option<(usize, &'static str)> {
    let mut chars = text.chars().enumerate();
    let mut opening = None;
    while let Some((index, c)) = chars.next() {
        match c {
            '"' => opening = if opening.is_some() { None } else { Some(index) },
            _ if opening.is_none() => continue,
            '\u{0}'..='\u{1f}' => return Some((index, "Invalid control character at")),
            '\\' => match chars.next() {
                Some((escape, 'u')) => {
                    if !(0..4).all(|_| {
                        chars
                            .next()
                            .is_some_and(|(_, digit)| digit.is_ascii_hexdigit())
                    }) {
                        return Some((escape, r"Invalid \uXXXX escape"));
                    }
                }
                Some((_, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't')) => {}
                Some(_) => return Some((index, r"Invalid \escape")),
                None => break,
            },
            _ => {}
        }
    }
    opening.map(|index| (index, "Unterminated string starting at"))
}

pub(crate) fn token_field(
    body: Value,
    field: &str,
    min: usize,
    max: usize,
) -> Result<String, Value> {
    if body.is_null() {
        return Err(json!({"loc":["body"],"type":"missing","msg":"Field required","input":null}));
    }
    if !body.is_object() {
        return Err(
            json!({"loc":["body"],"type":"model_attributes_type","msg":"Input should be a valid dictionary or object to extract fields from","input":body}),
        );
    }
    let Some(value) = body.get(field) else {
        return Err(
            json!({"loc":["body",field],"type":"missing","msg":"Field required","input":body}),
        );
    };
    let Some(token) = value.as_str() else {
        return Err(
            json!({"loc":["body",field],"type":"string_type","msg":"Input should be a valid string","input":value}),
        );
    };
    match token.chars().count() {
        n if n < min => Err(
            json!({"loc":["body",field],"type":"string_too_short","msg":format!("String should have at least {min} character{}", if min == 1 {""} else {"s"}),"input":token,"ctx":{"min_length":min.to_string()}}),
        ),
        n if n > max => Err(
            json!({"loc":["body",field],"type":"string_too_long","msg":format!("String should have at most {max} characters"),"input":token,"ctx":{"max_length":max.to_string()}}),
        ),
        _ => Ok(token.into()),
    }
}

pub(crate) fn integer(input: &Value) -> Result<i128, (&'static str, &'static str)> {
    match input {
        Value::Bool(v) => Ok(i128::from(*v)),
        Value::String(s) => {
            let digits = crate::query::integer(s)?;
            Ok(digits.parse().unwrap_or_else(|_| {
                if digits.starts_with('-') {
                    i128::MIN
                } else {
                    i128::MAX
                }
            }))
        }
        Value::Number(n) => {
            if let Some(v) = n.as_i64() {
                return Ok(i128::from(v));
            }
            if let Some(v) = n.as_u64() {
                return Ok(i128::from(v));
            }
            let v = n.as_f64().unwrap_or(f64::NAN);
            if v.fract() == 0.0 {
                Ok(v as i128)
            } else {
                Err((
                    "int_from_float",
                    "Input should be a valid integer, got a number with a fractional part",
                ))
            }
        }
        _ => Err(("int_type", "Input should be a valid integer")),
    }
}

#[cfg(test)]
mod syntax_tests {
    use super::*;

    #[test]
    fn string_errors_and_trailing_commas_use_character_offsets() {
        for (input, offset, message) in [
            (r#"["é","unfinished"#, 5, "Unterminated string starting at"),
            (r#"["é","\q"]"#, 6, r"Invalid \escape"),
            (
                r#"["é", ]"#,
                4,
                "Illegal trailing comma before end of array",
            ),
            (
                r#"{"é":1, }"#,
                6,
                "Illegal trailing comma before end of object",
            ),
        ] {
            let error = serde_json::from_str::<Value>(input).unwrap_err();
            let issue = json_issue(input.as_bytes(), error);
            assert_eq!(issue["loc"], json!(["body", offset]), "{input}");
            assert_eq!(issue["ctx"]["error"], message, "{input}");
        }
    }
}
