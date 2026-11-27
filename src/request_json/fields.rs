//! Decode single-field requests and retain exact submitted values for errors.
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

// Validators need only the submitted field. Large integers may be rejected as
// the wrong type, but their exact digits must survive in the error response.
pub(crate) fn validation_input<'a>(
    raw: &'a RawValue,
    key: &str,
) -> Result<(Value, &'a RawValue), Box<Response>> {
    let text = raw.get();
    if !text.starts_with('{') {
        return Ok((
            if text == "null" {
                Value::Null
            } else {
                json!([])
            },
            raw,
        ));
    }
    let fields: HashMap<String, &RawValue> =
        serde_json::from_str(text).map_err(|_| Box::new(internal_error()))?;
    Ok(match fields.get(key) {
        Some(value) => (json!({(key):field_value(value.get())}), *value),
        None => (json!({}), raw),
    })
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

pub(crate) async fn read_string(
    headers: &HeaderMap,
    stream: Body,
    key: &str,
    min: usize,
    max: usize,
) -> Result<String, Box<Response>> {
    let bytes = to_bytes(stream, usize::MAX)
        .await
        .map_err(|_| Box::new(internal_error()))?;
    let raw = document(headers, &bytes)?.ok_or_else(|| Box::new(internal_error()))?;
    let (body, original) = validation_input(&raw, key)?;
    request_json::token_field(body, key, min, max).map_err(|issue| {
        #[derive(Serialize)]
        struct Errors<'a> {
            detail: [FieldIssue<'a>; 1],
        }
        let errors = Errors {
            detail: [field_issue(issue, original)],
        };
        Box::new((StatusCode::UNPROCESSABLE_ENTITY, Json(errors)).into_response())
    })
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
