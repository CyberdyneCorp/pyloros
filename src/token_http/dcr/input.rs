use serde_json::{Value, json};

#[derive(Default)]
pub(super) struct Metadata {
    pub redirects: Vec<String>,
    pub name: Option<String>,
    pub grants: Vec<String>,
    pub responses: Vec<String>,
    pub method: Option<String>,
    pub scope: Option<String>,
}

fn strings(body: &Value, key: &str, required_list: bool, issues: &mut Vec<Value>) -> Vec<String> {
    let Some(value) = body.get(key) else {
        return Vec::new();
    };
    if value.is_null() && !required_list {
        return Vec::new();
    }
    let Some(values) = value.as_array() else {
        issues.push(json!({"type":"list_type","loc":["body",key],"msg":"Input should be a valid list","input":value}));
        return Vec::new();
    };
    if required_list && values.len() > 10 {
        issues.push(json!({"type":"too_long","loc":["body",key],"msg":format!("List should have at most 10 items after validation, not {}",values.len()),"input":value,"ctx":{"field_type":"List","max_length":"10","actual_length":values.len().to_string()}}));
        return Vec::new();
    }
    let mut result = Vec::new();
    for (index, item) in values.iter().enumerate() {
        if let Some(text) = item.as_str() {
            result.push(text.to_owned());
        } else {
            issues.push(json!({"type":"string_type","loc":["body",key,index],"msg":"Input should be a valid string","input":item}));
        }
    }
    result
}

fn string(body: &Value, key: &str, max: Option<usize>, issues: &mut Vec<Value>) -> Option<String> {
    let value = body.get(key).filter(|v| !v.is_null())?;
    let Some(text) = value.as_str() else {
        issues.push(json!({"type":"string_type","loc":["body",key],"msg":"Input should be a valid string","input":value}));
        return None;
    };
    if let Some(max) = max.filter(|n| text.chars().count() > *n) {
        issues.push(json!({"type":"string_too_long","loc":["body",key],"msg":format!("String should have at most {max} characters"),"input":value,"ctx":{"max_length":max.to_string()}}));
    }
    Some(text.to_owned())
}

pub(super) fn parse(body: Value) -> Result<Metadata, Vec<Value>> {
    if body.is_null() {
        return Err(vec![
            json!({"type":"missing","loc":["body"],"msg":"Field required","input":null}),
        ]);
    }
    if !body.is_object() {
        return Err(vec![
            json!({"type":"model_attributes_type","loc":["body"],"msg":"Input should be a valid dictionary or object to extract fields from","input":body}),
        ]);
    }
    let mut issues = Vec::new();
    let data = Metadata {
        redirects: strings(&body, "redirect_uris", true, &mut issues),
        name: string(&body, "client_name", Some(1024), &mut issues),
        grants: strings(&body, "grant_types", false, &mut issues),
        responses: strings(&body, "response_types", false, &mut issues),
        method: string(&body, "token_endpoint_auth_method", None, &mut issues),
        scope: string(&body, "scope", Some(2048), &mut issues),
    };
    if issues.is_empty() {
        Ok(data)
    } else {
        Err(issues)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlong_redirect_list_reports_one_length_error_before_item_errors() {
        let body = json!({"redirect_uris":vec![false;11],"scope":true});
        let Err(issues) = parse(body) else {
            panic!("invalid client metadata accepted")
        };
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0]["type"], "too_long");
        assert_eq!(issues[1]["loc"], json!(["body", "scope"]));
    }
}
