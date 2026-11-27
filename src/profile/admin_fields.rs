//! Shared validation for administrative REST request fields.
use super::*;
use crate::{login_http::problem, request_json};
use serde_json::Map;

pub(super) struct Fields<'a> {
    pub(super) body: &'a Map<String, Value>,
    pub(super) issues: Vec<Value>,
}
impl Fields<'_> {
    pub(super) fn string_list(&mut self, key: &str, nullable: bool) -> Option<Vec<String>> {
        let v = self.body.get(key)?;
        if nullable && v.is_null() {
            return None;
        }
        let Some(items) = v.as_array() else {
            self.issues.push(json!({"type":"list_type","loc":["body",key],"msg":"Input should be a valid list","input":v}));
            return None;
        };
        let mut values = Vec::new();
        for (i, item) in items.iter().enumerate() {
            if let Some(s) = item.as_str() {
                values.push(s.to_owned());
            } else {
                self.issues.push(json!({"type":"string_type","loc":["body",key,i],"msg":"Input should be a valid string","input":item}));
            }
        }
        Some(values)
    }

    pub(super) fn string(
        &mut self,
        key: &str,
        limit: Option<usize>,
        required: bool,
    ) -> Option<String> {
        let Some(v) = self.body.get(key) else {
            if required {
                self.issues.push(json!({"type":"missing","loc":["body",key],"msg":"Field required","input":self.body}));
            }
            return None;
        };
        if v.is_null() && !required {
            return None;
        }
        let Some(s) = v.as_str() else {
            self.issues.push(json!({"type":"string_type","loc":["body",key],"msg":"Input should be a valid string","input":v}));
            return None;
        };
        if required && s.is_empty() {
            self.issues.push(json!({"type":"string_too_short","loc":["body",key],"msg":"String should have at least 1 character","input":v,"ctx":{"min_length":"1"}}));
        } else if let Some(max) = limit.filter(|n| s.chars().count() > *n) {
            self.issues.push(json!({"type":"string_too_long","loc":["body",key],"msg":format!("String should have at most {max} characters"),"input":v,"ctx":{"max_length":max.to_string()}}));
        }
        Some(s.to_owned())
    }
    pub(super) fn boolean(&mut self, key: &str) -> bool {
        let Some(v) = self.body.get(key) else {
            return false;
        };
        if let Some(b) = v.as_bool() {
            return b;
        }
        let mut kind = "bool_type";
        let mut msg = "Input should be a valid boolean";
        if let Some(n) = v.as_f64() {
            if n == 0.0 || n == 1.0 {
                return n == 1.0;
            }
            if v.is_i64() || (v.is_f64() && n.fract() == 0.0 && n.abs() < 2f64.powi(63)) {
                kind = "bool_parsing";
                msg = "Input should be a valid boolean, unable to interpret input";
            }
        }
        if let Some(s) = v.as_str() {
            match s.to_ascii_lowercase().as_str() {
                "1" | "true" | "on" | "yes" | "y" | "t" => return true,
                "0" | "false" | "off" | "no" | "n" | "f" => return false,
                _ => {
                    kind = "bool_parsing";
                    msg = "Input should be a valid boolean, unable to interpret input";
                }
            }
        }
        self.issues
            .push(json!({"type":kind,"loc":["body",key],"msg":msg,"input":v}));
        false
    }
}

pub(super) fn object(body: &Value) -> Result<&Map<String, Value>, Vec<Value>> {
    object_field(body).map_err(|issue| vec![issue])
}

pub(super) fn object_field(body: &Value) -> Result<&Map<String, Value>, Value> {
    if body.is_null() {
        return Err(json!({"type":"missing","loc":["body"],"msg":"Field required","input":null}));
    }
    let Some(map) = body.as_object() else {
        return Err(
            json!({"type":"model_attributes_type","loc":["body"],"msg":"Input should be a valid dictionary or object to extract fields from","input":body}),
        );
    };
    Ok(map)
}

pub(super) fn body(headers: &HeaderMap, bytes: &[u8]) -> Result<Option<Value>, Box<Response>> {
    if !bytes.is_empty() && !request_json::is_json(headers) {
        return Ok(None);
    }
    let text = request_json::encoding::text(bytes).map_err(|_| {
        Box::new(problem(
            StatusCode::BAD_REQUEST,
            "There was an error parsing the body",
        ))
    })?;
    request_json::parse_body(headers, text.as_bytes())
        .map(Some)
        .map_err(|issue| {
            Box::new(
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({"detail":[issue]})),
                )
                    .into_response(),
            )
        })
}
