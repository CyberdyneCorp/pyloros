use axum::{
    Json,
    body::{Body, to_bytes},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

fn issue(field: &str, kind: &str, msg: &str, input: &Value) -> Value {
    json!({"loc":["body",field],"type":kind,"msg":msg,"input":input})
}

fn string<'a>(body: &'a Value, field: &str, errors: &mut Vec<Value>) -> Option<&'a str> {
    match body.get(field) {
        None => {
            errors.push(issue(field, "missing", "Field required", body));
            None
        }
        Some(Value::String(v)) => Some(v),
        Some(v) => {
            errors.push(issue(
                field,
                "string_type",
                "Input should be a valid string",
                v,
            ));
            None
        }
    }
}

fn address(raw: &str) -> Result<String, &'static str> {
    let raw = raw.trim();
    let (_, domain) = raw
        .rsplit_once('@')
        .ok_or("An email address must have an @-sign.")?;
    if domain.is_empty() {
        return Err("There must be something after the @-sign.");
    }
    if raw.starts_with('@') {
        return Err("There must be something before the @-sign.");
    }
    if raw.ends_with('.') {
        return Err("An email address cannot end with a period.");
    }
    let mailbox = raw
        .parse::<lettre::message::Mailbox>()
        .map_err(|_| "The email address is not valid.")?;
    let domain = mailbox.email.domain().to_lowercase();
    let (_, suffix) = domain
        .rsplit_once('.')
        .ok_or("The part after the @-sign is not valid. It should have a period.")?;
    if matches!(suffix, "test" | "invalid" | "localhost" | "local" | "onion") {
        return Err(
            "The part after the @-sign is a special-use or reserved name that cannot be used with email.",
        );
    }
    if suffix.chars().all(|c| c.is_ascii_digit()) {
        return Err(
            "The part after the @-sign is not valid. It is not within a valid top-level domain.",
        );
    }
    Ok(format!("{}@{domain}", mailbox.email.user()))
}

pub(super) fn credentials(body: &Value) -> Result<(String, String), Vec<Value>> {
    let mut errors = Vec::new();
    let raw = string(body, "email", &mut errors);
    let email = raw.map(address).transpose();
    if let Err(reason) = email {
        let mut error = issue(
            "email",
            "value_error",
            &format!("value is not a valid email address: {reason}"),
            &body["email"],
        );
        error["ctx"] = json!({"reason":reason});
        errors.push(error);
    }
    let password = string(body, "password", &mut errors);
    match (email.ok().flatten(), password) {
        (Some(email), Some(password)) if errors.is_empty() => Ok((email, password.into())),
        _ => Err(errors),
    }
}

pub(super) fn factor(body: &Value) -> Result<(String, String), Vec<Value>> {
    let mut errors = Vec::new();
    let token = string(body, "mfa_token", &mut errors);
    let code = string(body, "code", &mut errors);
    if let Some(code) = code {
        let length = code.chars().count();
        if length == 0 {
            errors.push(json!({"loc":["body","code"],"type":"string_too_short","msg":"String should have at least 1 character","input":code,"ctx":{"min_length":"1"}}));
        } else if length > 32 {
            errors.push(json!({"loc":["body","code"],"type":"string_too_long","msg":"String should have at most 32 characters","input":code,"ctx":{"max_length":"32"}}));
        }
    }
    match (token, code) {
        (Some(token), Some(code)) if errors.is_empty() => Ok((token.into(), code.into())),
        _ => Err(errors),
    }
}

pub(super) fn refresh(body: &Value) -> Result<Option<String>, Vec<Value>> {
    match body.get("refresh_token") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(token)) => Ok(Some(token.clone())),
        Some(other) => Err(vec![issue(
            "refresh_token",
            "string_type",
            "Input should be a valid string",
            other,
        )]),
    }
}

type Inputs<T> = Result<T, Vec<Value>>;

fn fields<T>(body: &Value, parse: fn(&Value) -> Inputs<T>) -> Inputs<T> {
    if body.is_null() {
        return Err(vec![
            json!({"loc":["body"],"type":"missing","msg":"Field required","input":null}),
        ]);
    }
    if !body.is_object() {
        return Err(vec![
            json!({"loc":["body"],"type":"model_attributes_type","msg":"Input should be a valid dictionary or object to extract fields from","input":body}),
        ]);
    }
    parse(body)
}

pub(super) async fn read<T>(
    headers: &HeaderMap,
    body: Body,
    parse: fn(&Value) -> Inputs<T>,
) -> Result<T, Response> {
    let bytes = to_bytes(body, 2 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE.into_response())?;
    crate::request_json::parse_body(headers, &bytes)
        .map_err(|e| vec![e])
        .and_then(|b| fields(&b, parse))
        .map_err(|issues| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":issues})),
            )
                .into_response()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_accepts_display_addresses_and_requires_a_public_email_domain() {
        assert_eq!(
            address("Member <member@EXAMPLE.com>").unwrap(),
            "member@example.com"
        );
        assert!(address("member@localhost").is_err());
        assert!(address("member@example.test").is_err());
        assert!(address("member@192.0.2.1").is_err());
        assert_eq!(
            credentials(&json!({"email":"bad","password":1}))
                .unwrap_err()
                .len(),
            2
        );
    }

    #[test]
    fn mfa_fields_report_individual_errors_and_preserve_submitted_codes() {
        let issues = fields(&json!({"mfa_token":false, "code":""}), factor).unwrap_err();
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0]["loc"], json!(["body", "mfa_token"]));
        assert_eq!(issues[1]["type"], "string_too_short");
        let (_, code) =
            fields(&json!({"mfa_token":"challenge","code":" 012345 "}), factor).unwrap();
        assert_eq!(code, " 012345 ");
    }
}
