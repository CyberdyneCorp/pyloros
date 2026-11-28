//! Decode request fields and retain exact submitted values for errors.
use crate::{
    login_http::{internal_error, problem},
    request_json,
};
use axum::{
    Json,
    body::{Body, to_bytes},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::{Value, json, value::RawValue};
use std::collections::HashMap;

// Preserve normalized digits beyond i128 for field validation and storage range checks.
pub(crate) fn integer_text(raw: &RawValue) -> Result<String, (&'static str, &'static str)> {
    let text = raw.get();
    let size_error = (
        "int_parsing_size",
        "Unable to parse input string as an integer, exceeded maximum size",
    );
    let digits = match text.as_bytes()[0] {
        b'"' => crate::query::integer(&serde_json::from_str::<String>(text).expect("JSON string"))?,
        b't' => return Ok("1".into()),
        b'f' => return Ok("0".into()),
        b'-' | b'0'..=b'9' if text.contains(['.', 'e', 'E']) => {
            let n = text.parse::<f64>().map_err(|_| size_error)?;
            if n.abs() >= -(i64::MIN as f64) {
                return Err(size_error);
            }
            if n.fract() != 0.0 {
                return Err((
                    "int_from_float",
                    "Input should be a valid integer, got a number with a fractional part",
                ));
            }
            return Ok((n as i64).to_string());
        }
        b'-' | b'0'..=b'9' => text.to_owned(),
        _ => return Err(("int_type", "Input should be a valid integer")),
    };
    let magnitude = digits
        .trim_start_matches(['+', '-'])
        .trim_start_matches('0');
    if magnitude.is_empty() {
        return Ok("0".into());
    }
    if digits.starts_with('-') {
        Ok(format!("-{magnitude}"))
    } else {
        Ok(magnitude.into())
    }
}

pub(crate) fn invalid(errors: Vec<(Value, &RawValue)>) -> Box<Response> {
    if errors.iter().any(|(_, input)| !finite_error_input(input)) {
        return Box::new(internal_error());
    }
    #[derive(Serialize)]
    struct Errors<'a> {
        detail: Vec<FieldIssue<'a>>,
    }
    let detail = errors
        .into_iter()
        .map(|(issue, input)| field_issue(issue, input))
        .collect();
    Box::new((StatusCode::UNPROCESSABLE_ENTITY, Json(Errors { detail })).into_response())
}

pub(crate) fn document(
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<Option<Box<RawValue>>, Box<Response>> {
    if bytes.is_empty() {
        return Ok(Some(RawValue::NULL.to_owned()));
    }
    if !request_json::is_json(headers) {
        return Ok(None);
    }
    let text = request_json::encoding::text(bytes).map_err(|_| {
        Box::new(problem(
            StatusCode::BAD_REQUEST,
            "There was an error parsing the body",
        ))
    })?;
    serde_json::from_str(&text).map(Some).map_err(|error| {
        Box::new(
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":[request_json::json_issue(text.as_bytes(),error)]})),
            )
                .into_response(),
        )
    })
}

#[derive(Serialize)]
pub(crate) struct FieldIssue<'a> {
    #[serde(flatten)]
    attributes: Value,
    input: &'a RawValue,
}

pub(crate) fn field_issue(mut attributes: Value, input: &RawValue) -> FieldIssue<'_> {
    attributes
        .as_object_mut()
        .expect("validation error object")
        .remove("input");
    FieldIssue { attributes, input }
}

// The reference error document can echo large integers, but cannot serialize
// an overflowing floating-point literal, including one inside a container.
pub(crate) fn finite_error_input(raw: &RawValue) -> bool {
    let mut text = raw.get();
    while let Some(byte) = text.as_bytes().first() {
        match byte {
            b'"' => {
                let mut string = serde_json::Deserializer::from_str(text).into_iter::<&RawValue>();
                if string.next().is_none_or(|v| v.is_err()) {
                    return false;
                }
                text = &text[string.byte_offset()..];
            }
            b'-' | b'0'..=b'9' => {
                let end = text
                    .find([',', ']', '}', ' ', '\t', '\r', '\n'])
                    .unwrap_or(text.len());
                let number = &text[..end];
                if number.contains(['.', 'e', 'E'])
                    && number.parse::<f64>().is_ok_and(|n| !n.is_finite())
                {
                    return false;
                }
                text = &text[end..];
            }
            _ => text = &text[1..],
        }
    }
    true
}

// Validators need only the submitted field. Large integers may be rejected as
// the wrong type, but their exact digits must survive in the error response.
pub(crate) fn validation_input<'a>(
    raw: &'a RawValue,
    key: &str,
) -> Result<(Value, &'a RawValue), Box<Response>> {
    let fields = object_fields(raw)?;
    let original = fields.get(key).copied().unwrap_or(raw);
    Ok((project(raw, &fields, &[key]), original))
}

pub(crate) fn object_fields(raw: &RawValue) -> Result<HashMap<String, &RawValue>, Box<Response>> {
    if raw.get().starts_with('{') {
        serde_json::from_str(raw.get()).map_err(|_| Box::new(internal_error()))
    } else {
        Ok(HashMap::new())
    }
}

pub(crate) fn project(raw: &RawValue, fields: &HashMap<String, &RawValue>, keys: &[&str]) -> Value {
    match raw.get().as_bytes().first() {
        Some(b'{') => Value::Object(
            keys.iter()
                .filter_map(|&key| {
                    fields
                        .get(key)
                        .map(|value| (key.to_owned(), field_value(value.get())))
                })
                .collect(),
        ),
        Some(b'n') => Value::Null,
        _ => json!([]),
    }
}

pub(crate) fn project_scalars(
    raw: &RawValue,
    submitted: &std::collections::HashMap<String, &RawValue>,
    keys: &[&str],
) -> Value {
    let mut projection = project(raw, submitted, keys);
    // A numeric literal outside the native JSON range is still a supplied value.
    for key in keys {
        if submitted.get(*key).is_some_and(|v| v.get() != "null") && projection[*key].is_null() {
            projection[*key] = json!([]);
        }
    }
    projection
}

fn field_value(text: &str) -> Value {
    match text.as_bytes().first() {
        Some(b'[') => json!([]),
        Some(b'{') => json!({}),
        // For a numeric literal outside the Value range, both scalar validators
        // report a type error. Its original representation is retained separately.
        _ => serde_json::from_str(text).unwrap_or(Value::Null),
    }
}

pub(crate) async fn read_fields<T>(
    headers: &HeaderMap,
    stream: Body,
    keys: &[&str],
    validate: impl FnOnce(Value) -> Result<T, Vec<Value>>,
) -> Result<T, Box<Response>> {
    let bytes = to_bytes(stream, usize::MAX)
        .await
        .map_err(|_| Box::new(internal_error()))?;
    let raw = super::iam_document::document(headers, &bytes)?
        .ok_or_else(|| Box::new(internal_error()))?;
    validate_scalar_document(&raw, keys, validate)
}

/// Validate only scalar model fields, preserving the distinction between null
/// and numeric literals outside the range of serde_json::Number.
pub(crate) fn validate_scalar_document<T>(
    raw: &RawValue,
    keys: &[&str],
    validate: impl FnOnce(Value) -> Result<T, Vec<Value>>,
) -> Result<T, Box<Response>> {
    let fields = object_fields(raw)?;
    validate(project_scalars(raw, &fields, keys)).map_err(|issues| {
        let errors = issues
            .into_iter()
            .map(|issue| {
                let original = issue["loc"]
                    .get(1)
                    .and_then(Value::as_str)
                    .and_then(|key| fields.get(key))
                    .copied()
                    .unwrap_or(raw);
                (issue, original)
            })
            .collect();
        invalid(errors)
    })
}

pub(crate) async fn read_string(
    headers: &HeaderMap,
    stream: Body,
    key: &str,
    min: usize,
    max: usize,
) -> Result<String, Box<Response>> {
    read_fields(headers, stream, &[key], |body| {
        request_json::token_field(body, key, min, max).map_err(|issue| vec![issue])
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn required_string_ignores_large_unrelated_fields_in_unicode_documents() {
        let input = json!({"ignored":"界".repeat(530_000),"token":"session"}).to_string();
        let mut bytes = vec![0xff, 0xfe, 0, 0];
        bytes.extend(input.chars().flat_map(|c| u32::from(c).to_le_bytes()));
        assert_eq!(
            read_string(&headers(), Body::from(bytes), "token", 1, 32)
                .await
                .unwrap(),
            "session"
        );
    }

    #[tokio::test]
    async fn token_input_ignores_unrelated_nonfinite_numbers_and_preserves_error_status() {
        let valid = Body::from(r#"{"token":"sample","other":NaN}"#);
        assert_eq!(
            read_string(&headers(), valid, "token", 1, 32)
                .await
                .unwrap(),
            "sample"
        );
        for wire in [r#"{"token":1e999}"#, r#"{"token":{"nested":[-Infinity]}}"#] {
            let error = read_string(&headers(), Body::from(wire), "token", 1, 32)
                .await
                .unwrap_err();
            assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    #[tokio::test]
    async fn wrong_type_preserves_submitted_integer_digits() {
        let input = r#"{"mfa_token":{"n":12345678901234567890123456789}}"#;
        let response = read_string(&headers(), Body::from(input), "mfa_token", 1, 4096)
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains(r#""input":{"n":12345678901234567890123456789}"#));
        assert!(text.contains(r#""loc":["body","mfa_token"]"#));
    }
}
