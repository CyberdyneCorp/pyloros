//! Preserve original field values and metadata key order in validation errors.
use super::creation::NewOrganization;
use super::*;
use crate::request_json::fields;
use crate::request_json::fields::invalid;
use indexmap::IndexMap;
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
    let projection = project(raw, &submitted, TEXT_FIELDS);
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
    let mut metadata = metadata(submitted.get("metadata").copied(), &mut errors)?;
    if !errors.is_empty() {
        return Err(invalid(errors));
    }
    metadata
        .as_object_mut()
        .expect("validated map")
        .retain(|_, v| v.as_str() != Some(""));
    Ok(NewOrganization {
        name: name.expect("validated required name"),
        short_name,
        domain,
        github,
        description,
        metadata,
    })
}

fn project(
    raw: &RawValue,
    submitted: &std::collections::HashMap<String, &RawValue>,
    keys: &[&str],
) -> Value {
    let mut projection = fields::project(raw, submitted, keys);
    // A numeric literal outside the native JSON range is still a supplied value.
    for key in keys {
        if submitted.get(*key).is_some_and(|v| v.get() != "null") && projection[*key].is_null() {
            projection[*key] = json!([]);
        }
    }
    projection
}

pub(super) fn patch(
    raw: &RawValue,
    path: &str,
) -> Result<(Uuid, serde_json::Map<String, Value>), Box<Response>> {
    let original_path = serde_json::value::to_raw_value(path).expect("string is JSON");
    let id = crate::query::path_uuid(path, "org_id");
    let mut errors = Vec::new();
    if let Err(issue) = &id {
        errors.push((issue.clone(), original_path.as_ref()));
    }
    let submitted = fields::object_fields(raw)?;
    let projection = project(
        raw,
        &submitted,
        &[
            "name",
            "short_name",
            "domain_name",
            "github_login",
            "description",
            "active",
        ],
    );
    let body = match admin_fields::object_field(&projection) {
        Ok(body) => body,
        Err(issue) => {
            errors.push((issue, raw));
            return Err(invalid(errors));
        }
    };
    let mut model = admin_fields::Fields {
        body,
        issues: Vec::new(),
    };
    let mut patch = text_patch(&mut model);
    for issue in model.issues.drain(..) {
        let key = issue["loc"][1].as_str().expect("field name");
        let input = submitted[key];
        errors.push((issue, input));
    }
    if let Some(value) = submitted.get("metadata") {
        let map = metadata(Some(value), &mut errors)?;
        patch.insert(
            "metadata".into(),
            if value.get() == "null" {
                Value::Null
            } else {
                map
            },
        );
    }
    if let Some(input) = body.get("active") {
        let active = if input.is_null() {
            Value::Null
        } else {
            json!(model.boolean("active"))
        };
        patch.insert("active".into(), active);
        errors.extend(
            model
                .issues
                .into_iter()
                .map(|issue| (issue, submitted["active"])),
        );
    }
    if !errors.is_empty() {
        return Err(invalid(errors));
    }
    Ok((id.expect("validated UUID"), patch))
}

fn text_patch(model: &mut admin_fields::Fields<'_>) -> serde_json::Map<String, Value> {
    let mut patch = serde_json::Map::new();
    for (key, limit) in [
        ("name", 200),
        ("short_name", 64),
        ("domain_name", 253),
        ("github_login", 39),
        ("description", 1024),
    ] {
        if let Some(input) = model.body.get(key) {
            let required = key == "name" && !input.is_null();
            patch.insert(
                key.to_owned(),
                json!(model.string(key, Some(limit), required)),
            );
        }
    }
    patch
}

type Issue<'a> = (Value, &'a RawValue);

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

    #[test]
    fn overflow_in_the_active_flag_cannot_deactivate_an_organization() {
        let raw = serde_json::from_str(r#"{"active":1e999}"#).unwrap();
        let error = patch(raw, &Uuid::new_v4().to_string()).unwrap_err();
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn edits_distinguish_omitted_fields_null_and_metadata_removals() {
        let raw = serde_json::from_str(
            r#"{"name":null,"active":null,"short_name":"","metadata":{"retired":""},"extra":10}"#,
        )
        .unwrap();
        let id = Uuid::new_v4();
        let (target, fields) = patch(raw, &id.to_string()).unwrap();
        assert_eq!(target, id);
        assert_eq!(
            Value::Object(fields),
            json!({"name":null,"active":null,"short_name":"","metadata":{"retired":""}})
        );
    }

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
