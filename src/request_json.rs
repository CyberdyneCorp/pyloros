use crate::token_http::header;
use axum::http::HeaderMap;
use serde_json::{Value, json};

pub(crate) fn parse_body(headers: &HeaderMap, bytes: &[u8]) -> Result<Value, Value> {
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    let mime = header(headers, "content-type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !mime
        .strip_prefix("application/")
        .is_some_and(|s| s == "json" || s.ends_with("+json"))
    {
        return Ok(Value::String(String::from_utf8_lossy(bytes).into_owned()));
    }
    serde_json::from_slice(bytes).map_err(|error| json_issue(bytes, error))
}

fn json_issue(bytes: &[u8], error: serde_json::Error) -> Value {
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
    json!({"loc":["body",prefix.chars().count()],"type":"json_invalid","msg":"JSON decode error","input":{},"ctx":{"error":message}})
}
