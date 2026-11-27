use axum::{
    Json,
    body::{Body, to_bytes},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

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

fn check_dots_and_hyphens(local: &str, domain: &str) -> Result<(), &'static str> {
    if local.starts_with('.') {
        return Err("An email address cannot start with a period.");
    }
    if local.ends_with('.') {
        return Err("An email address cannot have a period immediately before the @-sign.");
    }
    if domain.starts_with('.') {
        return Err("An email address cannot have a period immediately after the @-sign.");
    }
    if domain.starts_with('-') {
        return Err("An email address cannot have a hyphen immediately after the @-sign.");
    }
    if domain.ends_with('-') {
        return Err("An email address cannot end with a hyphen.");
    }
    if domain.contains("-.") || domain.contains(".-") {
        return Err("An email address cannot have a period and a hyphen next to each other.");
    }
    if local.contains("..") || domain.contains("..") {
        return Err("An email address cannot have two periods in a row.");
    }
    Ok(())
}

fn address(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let addr = raw
        .strip_suffix('>')
        .and_then(|display| display.rsplit_once('<'))
        .map_or(raw, |(_, email)| email.trim());
    let (local, domain) = addr
        .split_once('@')
        .ok_or_else(|| super::email_domain::missing_separator(addr))?;
    if domain.is_empty() {
        return Err("There must be something after the @-sign.".into());
    }
    if local.is_empty() {
        return Err("There must be something before the @-sign.".into());
    }
    super::email_domain::characters(domain)?;
    if domain.ends_with('.') {
        return Err("An email address cannot end with a period.".into());
    }
    check_dots_and_hyphens(local, domain)?;
    let domain = super::email_domain::validate(domain)?;
    let mailbox = raw
        .parse::<lettre::message::Mailbox>()
        .map_err(|_| "The email address is not valid.")?;
    let local: String = mailbox.email.user().nfc().collect();
    Ok(format!("{local}@{domain}"))
}

pub(crate) fn email_field(body: &Value) -> Result<String, Vec<Value>> {
    let mut errors = Vec::new();
    let raw = string(body, "email", &mut errors).ok_or(errors)?;
    address(raw).map_err(|reason| {
        let mut error = issue(
            "email",
            "value_error",
            &format!("value is not a valid email address: {reason}"),
            &body["email"],
        );
        error["ctx"] = json!({"reason":reason});
        vec![error]
    })
}

pub(super) fn credentials(body: &Value) -> Result<(String, String), Vec<Value>> {
    let (email, mut errors) = match email_field(body) {
        Ok(email) => (Some(email), Vec::new()),
        Err(issues) => (None, issues),
    };
    let password = string(body, "password", &mut errors);
    match (email, password) {
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
) -> Result<T, Box<Response>> {
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
        .map_err(Box::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_errors_precede_account_lookup() {
        for (input, expected) in [
            (
                "user@a_+b.com",
                "The part after the @-sign contains invalid characters: '+', '_'.",
            ),
            (
                "user@site.arpa",
                "The part after the @-sign is a special-use or reserved name that cannot be used with email.",
            ),
            (
                "user@one.c1",
                "The part after the @-sign is not valid. It is not within a valid top-level domain.",
            ),
            (
                "user@[IPv6:::1]",
                "A bracketed IP address after the @-sign is not allowed here.",
            ),
        ] {
            assert_eq!(address(input).unwrap_err(), expected);
        }
        assert!(address("user@one.1c").is_ok());
        assert_eq!(
            address(&format!("user@{}.com", "x".repeat(64))).unwrap_err(),
            "After the @-sign, periods cannot be separated by so many characters (1 character too many)."
        );
    }

    #[test]
    fn account_addresses_share_a_unicode_spelling_before_lookup() {
        for submitted in [
            "Cafe\u{301}@xn--bcher-kva.de",
            "Name <Café@BÜCHER.DE>",
            "Café@bu\u{308}cher.de",
        ] {
            assert_eq!(address(submitted).unwrap(), "Café@bücher.de");
        }
    }

    #[test]
    fn malformed_email_diagnostics_apply_to_the_address_inside_a_display_name() {
        assert_eq!(
            address("A <a..b@example.com>"),
            Err("An email address cannot have two periods in a row.".into())
        );
        assert_eq!(
            address("a@-example.com"),
            Err("An email address cannot have a hyphen immediately after the @-sign.".into())
        );
        assert_eq!(address("A..B <a@example.com>").unwrap(), "a@example.com");
    }

    #[tokio::test]
    async fn invalid_json_returns_a_validation_response_to_the_http_handler() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let response = read(&headers, Body::from("{"), credentials)
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["detail"][0]["type"], "json_invalid");
    }

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
