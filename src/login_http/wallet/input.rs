use super::*;
use crate::request_json::fields;
use serde_json::value::RawValue;

pub(super) fn parse(raw: &RawValue) -> Result<(Uuid, String), Box<Response>> {
    if !raw.get().starts_with('{') {
        let issue = if raw.get() == "null" {
            json!({"type":"missing","loc":["body"],"msg":"Field required"})
        } else {
            json!({"type":"model_attributes_type","loc":["body"],"msg":"Input should be a valid dictionary or object to extract fields from"})
        };
        return Err(fields::invalid(vec![(issue, raw)]));
    }
    let source = fields::object_fields(raw)?;
    let mut errors = Vec::new();
    let mut id = None;
    let mut signature = None;
    for field in ["challenge_id", "signature"] {
        let loc = ["body", field];
        let Some(&value) = source.get(field) else {
            errors.push((
                json!({"loc":loc,"type":"missing","msg":"Field required"}),
                raw,
            ));
            continue;
        };
        match (field, serde_json::from_str::<String>(value.get())) {
            ("challenge_id", Ok(text)) => match crate::query::uuid_field(&text, "body", field) {
                Ok(parsed) => id = Some(parsed),
                Err(issue) => errors.push((issue, value)),
            },
            ("challenge_id", Err(_)) => {
                let issue = json!({
                    "loc": loc, "type":"uuid_type",
                    "msg": "UUID input should be a string, bytes or UUID object"
                });
                errors.push((issue, value));
            }
            (_, Ok(text)) => signature = Some(text),
            (_, Err(_)) => {
                let issue = json!({"loc":loc, "type":"string_type", "msg":"Input should be a valid string"});
                errors.push((issue, value));
            }
        }
    }
    match (id, signature) {
        (Some(id), Some(signature)) => Ok((id, signature)),
        _ => Err(fields::invalid(errors)),
    }
}
