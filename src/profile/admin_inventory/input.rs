//! Project only IAM request fields, retaining submitted JSON for nested validation errors.
use super::*;
use crate::request_json::fields::{FieldIssue, field_issue, finite_error_input, object_fields};
use serde_json::value::RawValue;

enum Shape {
    Identifier,
    String,
    Object(&'static [Field]),
    List(&'static Shape),
}
struct Field(&'static str, &'static Shape, Presence);
use Presence::{DefaultList, Nullable, Required};
enum Presence {
    Required,
    Nullable,
    DefaultList,
}
use Shape::{List, Object, String as Text};

const CONDITIONS: Shape = List(&Object(&[
    Field("operator", &Text, Required),
    Field("key", &Text, Required),
    Field("value", &Text, Required),
]));
const STATEMENTS: Shape = List(&Object(&[
    Field("effect", &Text, Required),
    Field("actions", &List(&Text), Required),
    Field("resources", &List(&Text), Required),
    Field("conditions", &CONDITIONS, DefaultList),
    Field("sid", &Text, Nullable),
]));
const REPLACE: Shape = Object(&[
    Field("name", &Text, Nullable),
    Field("description", &Text, Nullable),
    Field("statements", &STATEMENTS, Required),
]);
const CREATE: Shape = Object(&[
    Field("name", &Text, Required),
    Field("description", &Text, Nullable),
    Field("statements", &STATEMENTS, Required),
]);

#[derive(Default)]
struct Errors<'a> {
    detail: Vec<FieldIssue<'a>>,
}

impl<'a> Errors<'a> {
    fn response(self, path: Option<Value>) -> Box<Response> {
        #[derive(Serialize)]
        #[serde(untagged)]
        enum Issue<'a> {
            Path(Value),
            Body(FieldIssue<'a>),
        }
        #[derive(Serialize)]
        struct Invalid<'a> {
            detail: Vec<Issue<'a>>,
        }
        let detail = path
            .into_iter()
            .map(Issue::Path)
            .chain(self.detail.into_iter().map(Issue::Body))
            .collect();
        Box::new((StatusCode::UNPROCESSABLE_ENTITY, Json(Invalid { detail })).into_response())
    }

    fn reject(
        &mut self,
        raw: &'a RawValue,
        loc: &[Value],
        kind: &str,
        msg: &str,
    ) -> Result<Value, Box<Response>> {
        if !finite_error_input(raw) {
            return Err(Box::new(internal()));
        }
        self.detail
            .push(field_issue(json!({"loc":loc,"type":kind,"msg":msg}), raw));
        Ok(Value::Null)
    }
    fn project(
        &mut self,
        raw: &'a RawValue,
        loc: &mut Vec<Value>,
        shape: &Shape,
    ) -> Result<Value, Box<Response>> {
        match shape {
            Shape::Identifier => {
                let Ok(text) = serde_json::from_str::<String>(raw.get()) else {
                    return self.reject(
                        raw,
                        loc,
                        "uuid_type",
                        "UUID input should be a string, bytes or UUID object",
                    );
                };
                match crate::query::uuid_field(&text, "body", "policy_id") {
                    Ok(id) => Ok(json!(id)),
                    Err(issue) => {
                        self.detail.push(field_issue(issue, raw));
                        Ok(Value::Null)
                    }
                }
            }
            Text => match serde_json::from_str::<String>(raw.get()) {
                Ok(s) => Ok(Value::String(s)),
                Err(_) => self.reject(raw, loc, "string_type", "Input should be a valid string"),
            },
            List(item) => {
                let Ok(items) = serde_json::from_str::<Vec<&RawValue>>(raw.get()) else {
                    return self.reject(raw, loc, "list_type", "Input should be a valid list");
                };
                let mut values = Vec::with_capacity(items.len());
                for (index, entry) in items.into_iter().enumerate() {
                    loc.push(json!(index));
                    values.push(self.project(entry, loc, item)?);
                    loc.pop();
                }
                Ok(Value::Array(values))
            }
            Object(fields) => self.object(raw, loc, fields),
        }
    }
    fn object(
        &mut self,
        raw: &'a RawValue,
        loc: &mut Vec<Value>,
        fields: &[Field],
    ) -> Result<Value, Box<Response>> {
        if !raw.get().starts_with('{') {
            return self.reject(
                raw,
                loc,
                "model_attributes_type",
                "Input should be a valid dictionary or object to extract fields from",
            );
        }
        let source = object_fields(raw)?;
        let mut result = serde_json::Map::new();
        for Field(key, shape, presence) in fields {
            loc.push(json!(key));
            let value = match (source.get(*key), presence) {
                (None, Required) => self.reject(raw, loc, "missing", "Field required")?,
                (None, DefaultList) => json!([]),
                (None, Nullable) => Value::Null,
                (Some(v), Nullable) if v.get() == "null" => Value::Null,
                (Some(v), _) => self.project(v, loc, shape)?,
            };
            loc.pop();
            result.insert((*key).into(), value);
        }
        Ok(Value::Object(result))
    }
}

pub(super) fn group_policy(
    raw: &RawValue,
    group: Result<Uuid, Value>,
) -> Result<(Uuid, Uuid), Box<Response>> {
    const LINK: Shape = Object(&[Field("policy_id", &Shape::Identifier, Required)]);
    let (group, body) = project(raw, &LINK, Some(group))?;
    Ok((
        group.expect("group path supplied"),
        serde_json::from_value(body["policy_id"].clone()).expect("validated UUID"),
    ))
}

pub(super) fn group(raw: &RawValue) -> Result<Value, Box<Response>> {
    const GROUP: Shape = Object(&[
        Field("name", &Text, Required),
        Field("description", &Text, Nullable),
    ]);
    project(raw, &GROUP, None).map(|(_, body)| body)
}

pub(super) fn parse(
    raw: &RawValue,
    path: Option<Result<Uuid, Value>>,
) -> Result<(Option<Uuid>, Value), Box<Response>> {
    let shape = if path.is_some() { &REPLACE } else { &CREATE };
    let (id, body) = project(raw, shape, path)?;
    validate_statements(&body)?;
    Ok((id, body))
}

fn project(
    raw: &RawValue,
    shape: &Shape,
    path: Option<Result<Uuid, Value>>,
) -> Result<(Option<Uuid>, Value), Box<Response>> {
    let mut errors = Errors::default();
    let mut loc = vec![json!("body")];
    let body = if raw.get() == "null" {
        errors.reject(raw, &loc, "missing", "Field required")?
    } else {
        errors.project(raw, &mut loc, shape)?
    };
    let id = match path.transpose() {
        Ok(id) if errors.detail.is_empty() => id,
        result => return Err(errors.response(result.err())),
    };
    Ok((id, body))
}

fn validate_statements(policy: &Value) -> Result<(), Box<Response>> {
    for statement in policy["statements"]
        .as_array()
        .expect("validated statements")
    {
        let effect = statement["effect"].as_str().expect("validated effect");
        if !matches!(effect, "allow" | "deny") {
            return Err(invalid(effect, "Effect"));
        }
        for condition in statement["conditions"]
            .as_array()
            .expect("validated conditions")
        {
            let operator = &condition["operator"];
            if serde_json::from_value::<statements::Operator>(operator.clone()).is_err() {
                return Err(invalid(
                    operator.as_str().expect("validated operator"),
                    "ConditionOperator",
                ));
            }
        }
    }
    Ok(())
}

fn invalid(value: &str, kind: &str) -> Box<Response> {
    let quoted = crate::browser_prompt::quoted_string(value);
    Box::new(crate::login_http::problem(
        StatusCode::BAD_REQUEST,
        &format!("invalid policy statement: {quoted} is not a valid {kind}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replacement_lists_path_then_body_errors_and_accepts_omitted_metadata() {
        let id = Uuid::new_v4();
        let (_, policy) = parse(
            serde_json::from_str(r#"{"statements":[]}"#).unwrap(),
            Some(Ok(id)),
        )
        .unwrap();
        assert!(policy["name"].is_null());
        let invalid = crate::query::path_uuid("bad", "policy_id");
        let error = parse(serde_json::from_str("{}").unwrap(), Some(invalid)).unwrap_err();
        let bytes = axum::body::to_bytes(error.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["detail"][0]["loc"], json!(["path", "policy_id"]));
        assert_eq!(doc["detail"][1]["loc"], json!(["body", "statements"]));
    }

    #[tokio::test]
    async fn nested_type_errors_preserve_arbitrary_integer_inputs_before_effect_validation() {
        let body = r#"{"name":"example","statements":[{"effect":"unknown","actions":[12345678901234567890123456789],"resources":[]}]}"#;
        let response = parse(serde_json::from_str(body).unwrap(), None).unwrap_err();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let errors = std::str::from_utf8(&bytes).unwrap();
        assert!(errors.contains(r#""input":12345678901234567890123456789"#));
        assert!(errors.contains(r#""loc":["body","statements",0,"actions",0]"#));
    }
}
