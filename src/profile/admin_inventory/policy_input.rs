//! Project only policy fields, retaining submitted JSON for nested validation errors.
use super::*;
use crate::request_json::fields::{FieldIssue, field_issue, finite_error_input, object_fields};
use serde_json::value::RawValue;

enum Shape {
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
const CREATE: Shape = Object(&[
    Field("name", &Text, Required),
    Field("description", &Text, Nullable),
    Field("statements", &STATEMENTS, Required),
]);

#[derive(Default, Serialize)]
struct Errors<'a> {
    detail: Vec<FieldIssue<'a>>,
}

impl<'a> Errors<'a> {
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

pub(super) fn create(raw: &RawValue) -> Result<Value, Box<Response>> {
    let mut errors = Errors::default();
    let mut loc = vec![json!("body")];
    let policy = if raw.get() == "null" {
        errors.reject(raw, &loc, "missing", "Field required")?
    } else {
        errors.project(raw, &mut loc, &CREATE)?
    };
    if !errors.detail.is_empty() {
        return Err(Box::new(
            (StatusCode::UNPROCESSABLE_ENTITY, Json(errors)).into_response(),
        ));
    }
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
    Ok(policy)
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
    async fn nested_type_errors_preserve_arbitrary_integer_inputs_before_effect_validation() {
        let body = r#"{"name":"example","statements":[{"effect":"unknown","actions":[12345678901234567890123456789],"resources":[]}]}"#;
        let response = create(serde_json::from_str(body).unwrap()).unwrap_err();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let errors = std::str::from_utf8(&bytes).unwrap();
        assert!(errors.contains(r#""input":12345678901234567890123456789"#));
        assert!(errors.contains(r#""loc":["body","statements",0,"actions",0]"#));
    }
}
