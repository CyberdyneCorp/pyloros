//! Preserve original field values and metadata key order in validation errors.
use super::*;
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::value::RawValue;

const TEXT_FIELDS: &[&str] = &[
    "name",
    "short_name",
    "domain_name",
    "github_login",
    "description",
];

pub(super) fn parse(raw: &RawValue) -> Result<NewOrganization, Box<Response>> {
    let submitted = fields::object_fields(raw)?;
    let mut projection = fields::project(raw, &submitted, TEXT_FIELDS);
    // A numeric literal outside the native JSON range is still a supplied value.
    for key in TEXT_FIELDS {
        if submitted.get(*key).is_some_and(|v| v.get() != "null") && projection[*key].is_null() {
            projection[*key] = json!(false);
        }
    }
    let mut errors = Vec::new();
    let body =
        admin_fields::object_field(&projection).map_err(|issue| invalid(vec![(issue, raw)]))?;
    let mut model = admin_fields::Fields {
        body,
        issues: Vec::new(),
    };
    let name = model.string("name", Some(200), true);
    let short_name = model.string("short_name", Some(64), false);
    let domain = model.string("domain_name", Some(253), false);
    let github = model.string("github_login", Some(39), false);
    let description = model.string("description", Some(1024), false);
    for issue in model.issues {
        let input = issue["loc"][1]
            .as_str()
            .and_then(|k| submitted.get(k))
            .copied()
            .unwrap_or(raw);
        errors.push((issue, input));
    }
    let metadata = metadata(submitted.get("metadata").copied(), &mut errors)?;
    if !errors.is_empty() {
        return Err(invalid(errors));
    }
    Ok(NewOrganization {
        name: name.expect("validated required name"),
        short_name,
        domain,
        github,
        description,
        metadata,
    })
}

type Issue<'a> = (Value, &'a RawValue);

fn invalid(errors: Vec<Issue<'_>>) -> Box<Response> {
    if errors
        .iter()
        .any(|(_, input)| !fields::finite_error_input(input))
    {
        return Box::new(internal());
    }
    #[derive(Serialize)]
    struct Errors<'a> {
        detail: Vec<fields::FieldIssue<'a>>,
    }
    let detail = errors
        .into_iter()
        .map(|(issue, input)| fields::field_issue(issue, input))
        .collect();
    Box::new((StatusCode::UNPROCESSABLE_ENTITY, Json(Errors { detail })).into_response())
}

fn metadata<'a>(
    raw: Option<&'a RawValue>,
    errors: &mut Vec<Issue<'a>>,
) -> Result<Value, Box<Response>> {
    let Some(raw) = raw.filter(|v| v.get() != "null") else {
        return Ok(json!({}));
    };
    if !raw.get().starts_with('{') {
        errors.push((json!({"type":"dict_type","loc":["body","metadata"],"msg":"Input should be a valid dictionary"}),raw));
        return Ok(Value::Null);
    }
    let map: IndexMap<String, &RawValue> =
        serde_json::from_str(raw.get()).map_err(|_| Box::new(internal()))?;
    let mut values = IndexMap::with_capacity(map.len());
    for (key, entry) in &map {
        if let Ok(value) = serde_json::from_str::<String>(entry.get()) {
            values.insert(key.as_str(), value);
        } else {
            errors.push((json!({"type":"string_type","loc":["body","metadata",key],"msg":"Input should be a valid string"}),*entry));
        }
    }
    if values.len() == map.len()
        && let Some(message) = bounds(&values)
    {
        errors.push((json!({"type":"value_error","loc":["body","metadata"],"msg":format!("Value error, {message}"),"ctx":{"error":message}}),raw));
    }
    values.retain(|_, v| !v.is_empty());
    Ok(json!(values))
}

fn bounds(values: &IndexMap<&str, String>) -> Option<&'static str> {
    if values.len() > 25 {
        return Some("at most 25 metadata entries");
    }
    for (key, value) in values {
        if key.is_empty() || key.chars().count() > 64 {
            return Some("metadata keys must be 1-64 chars");
        }
        if value.chars().count() > 512 {
            return Some("metadata values must be <= 512 chars");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_metadata_values_keep_submission_order_and_exact_integers() {
        let text = r#"{"name":"test","metadata":{"z":987654321012345678909876,"a":[1]}}"#;
        let error = parse(serde_json::from_str(text).unwrap()).err().unwrap();
        assert_eq!(error.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(error.into_body(), 4096).await.unwrap();
        let document = std::str::from_utf8(&bytes).unwrap();
        assert!(document.contains("987654321012345678909876"));
        let detail: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(detail["detail"][0]["loc"], json!(["body", "metadata", "z"]));
        assert_eq!(detail["detail"][1]["loc"], json!(["body", "metadata", "a"]));
    }

    #[test]
    fn overflowing_optional_text_input_cannot_become_an_omitted_field() {
        let text = r#"{"name":"test","short_name":1e999}"#;
        let error = parse(serde_json::from_str(text).unwrap()).err().unwrap();
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
