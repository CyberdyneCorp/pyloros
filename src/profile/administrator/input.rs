//! Validate single-field administrative updates while retaining the submitted JSON
//! in validation errors, including integers outside the native JSON number range.
use super::*;
use crate::request_json;
use serde::Serialize;
use serde_json::value::RawValue;
use std::collections::HashMap;

pub(super) fn document(
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
        Box::new(password_change::invalid(vec![request_json::json_issue(
            text.as_bytes(),
            error,
        )]))
    })
}

#[derive(Serialize)]
struct FieldIssue<'a> {
    #[serde(flatten)]
    attributes: Value,
    input: &'a RawValue,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Issue<'a> {
    Path(Value),
    Field(FieldIssue<'a>),
}

#[derive(Serialize)]
struct Errors<'a> {
    detail: Vec<Issue<'a>>,
}

pub(super) fn validate<T>(
    path: &str,
    raw: &RawValue,
    key: &str,
    parse: impl FnOnce(Value) -> Result<T, Value>,
) -> Result<(Uuid, T), Box<Response>> {
    let user = crate::query::path_uuid(path, "user_id");
    let (body, original) = validation_input(raw, key)?;
    match (user, parse(body)) {
        (Ok(user), Ok(input)) => Ok((user, input)),
        (user, input) => {
            let mut detail = Vec::new();
            if let Err(issue) = user {
                detail.push(Issue::Path(issue));
            }
            if let Err(mut issue) = input {
                issue
                    .as_object_mut()
                    .expect("field validator returns an object")
                    .remove("input");
                detail.push(Issue::Field(FieldIssue {
                    attributes: issue,
                    input: original,
                }));
            }
            Err(Box::new(
                (StatusCode::UNPROCESSABLE_ENTITY, Json(Errors { detail })).into_response(),
            ))
        }
    }
}

// Validators need only the submitted field. Large integers may be rejected as
// the wrong type, but their exact digits must survive in the error response.
fn validation_input<'a>(
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
        serde_json::from_str(text).map_err(|_| Box::new(internal()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn invalid_role_values_keep_the_submitted_integer_in_the_response() {
        let digits = "1844674407370955161700009";
        let raw = serde_json::value::RawValue::from_string(format!(r#"{{"is_admin":{digits}}}"#))
            .unwrap();
        let result = validate(
            &Uuid::nil().to_string(),
            &raw,
            "is_admin",
            crate::profile::admin_role::status_field,
        );
        let response = result.unwrap_err();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        assert!(body.contains(&format!(r#""input":{digits}"#)));
        assert!(body.contains(r#""type":"bool_type""#));
    }
}
