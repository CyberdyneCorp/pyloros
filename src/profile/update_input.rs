//! Validate single-field updates while retaining the submitted JSON
//! in validation errors, including integers outside the native JSON number range.
use super::*;
use crate::login_http::problem;
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
            if let Err(issue) = input {
                detail.push(field_issue(issue, original));
            }
            Err(Box::new(
                (StatusCode::UNPROCESSABLE_ENTITY, Json(Errors { detail })).into_response(),
            ))
        }
    }
}

fn field_issue(mut attributes: Value, input: &RawValue) -> Issue<'_> {
    attributes
        .as_object_mut()
        .expect("validation error object")
        .remove("input");
    Issue::Field(FieldIssue { attributes, input })
}

pub(super) fn nullable_string(raw: &RawValue, key: &str) -> Result<Option<String>, Box<Response>> {
    let (body, input) = validation_input(raw, key)?;
    let issue = match super::admin_fields::object_field(&body) {
        Err(issue) => issue,
        Ok(_) if input.get() == "null" || body.get(key).is_none() => return Ok(None),
        Ok(_) if body[key].is_string() => return Ok(body[key].as_str().map(str::to_owned)),
        Ok(_) => {
            json!({"loc":["body",key],"type":"string_type","msg":"Input should be a valid string"})
        }
    };
    let detail = vec![field_issue(issue, input)];
    Err(Box::new(
        (StatusCode::UNPROCESSABLE_ENTITY, Json(Errors { detail })).into_response(),
    ))
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

#[cfg(test)]
mod phone_tests {
    use super::*;

    #[tokio::test]
    async fn invalid_phone_preserves_nested_large_integers() {
        let raw = RawValue::from_string(r#"{"phone":[12345678901234567890001]}"#.into()).unwrap();
        let response = nullable_string(&raw, "phone").unwrap_err();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains(r#""input":[12345678901234567890001]"#)
        );
    }
}
