//! Decode the envelope without rounding integers or reordering the provider's error.
use super::{ReadError, RpcRead, Value};
use serde_json::value::RawValue;
use std::collections::HashMap;

#[derive(Debug)]
pub(super) struct RpcError {
    pub(super) code: Option<i64>,
    pub(super) message: String,
    pub(super) data: Option<Box<RawValue>>,
    pub(super) diagnostic: String,
}

pub(super) fn decode(body: &[u8], read: RpcRead) -> Result<Value, ReadError> {
    let raw: &RawValue = serde_json::from_slice(body).map_err(|e| invalid_json(body, e))?;
    if !raw.get().starts_with('{') {
        let rendered = if raw.get().starts_with('"') {
            serde_json::from_str(raw.get()).map_err(|_| ReadError::Failure)?
        } else {
            crate::json_representation::representation(raw).map_err(|_| ReadError::Failure)?
        };
        return Err(ReadError::Diagnostic(format!(
            "Malformed response: expected a valid JSON-RPC response object, got: `{rendered}`"
        )));
    }
    let fields: HashMap<String, &RawValue> =
        serde_json::from_str(raw.get()).map_err(|_| ReadError::Failure)?;
    let version = fields
        .get("jsonrpc")
        .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok());
    match read {
        RpcRead::Contract | RpcRead::TransactionQuantity(_)
            if version.as_deref() != Some("2.0")
                || fields.get("id").map(|r| r.get()) != Some("1") =>
        {
            return Err(ReadError::Failure);
        }
        RpcRead::Health => validate_health(raw, &fields, version.as_deref())?,
        _ => {}
    }
    if let Some(error) = fields.get("error") {
        let fields =
            serde_json::from_str::<HashMap<String, &RawValue>>(error.get()).unwrap_or_default();
        let diagnostic =
            crate::json_representation::representation(error).map_err(|_| ReadError::Failure)?;
        return Err(ReadError::Rpc(Box::new(RpcError {
            code: fields.get("code").and_then(|raw| raw.get().parse().ok()),
            message: fields
                .get("message")
                .and_then(|raw| serde_json::from_str(raw.get()).ok())
                .unwrap_or_default(),
            data: fields.get("data").map(|raw| (*raw).to_owned()),
            diagnostic,
        })));
    }
    let result = fields
        .get("result")
        .ok_or_else(|| bad_format(raw, r#"Response must include either "error" or "result"."#))?;
    if let RpcRead::TransactionQuantity(kind) = read {
        return kind.decode(result);
    }
    serde_json::from_str(result.get()).map_err(|_| ReadError::Failure)
}

fn bad_format(raw: &RawValue, reason: &str) -> ReadError {
    let Ok(rendered) = crate::json_representation::representation(raw) else {
        return ReadError::Failure;
    };
    ReadError::Diagnostic(format!(
        "The response was in an unexpected format and unable to be parsed. {reason} The raw response is: {rendered}"
    ))
}

fn validate_health(
    raw: &RawValue,
    fields: &HashMap<String, &RawValue>,
    version: Option<&str>,
) -> Result<(), ReadError> {
    if version != Some("2.0") {
        return Err(bad_format(
            raw,
            r#"The "jsonrpc" field must be present with a value of "2.0"."#,
        ));
    }
    let Some(id) = fields.get("id") else {
        return Err(bad_format(
            raw,
            r#"Response must include an "id" field or be formatted as an `eth_subscription` response."#,
        ));
    };
    if !valid_health_id(id, fields.contains_key("error")) {
        return Err(bad_format(
            raw,
            r#""id" must be an integer or a string representation of an integer."#,
        ));
    }
    let Some(error) = fields.get("error") else {
        return Ok(());
    };
    if fields.contains_key("result") {
        return Err(bad_format(
            raw,
            r#"Response cannot include both "error" and "result"."#,
        ));
    }
    let Ok(error) = serde_json::from_str::<HashMap<String, &RawValue>>(error.get()) else {
        return Err(bad_format(
            raw,
            r#"response["error"] must be a valid object as defined by the JSON-RPC 2.0 specification."#,
        ));
    };
    if !error
        .get("message")
        .is_some_and(|v| v.get().starts_with('"'))
    {
        return Err(bad_format(
            raw,
            r#"error["message"] is required and must be a string value."#,
        ));
    }
    if !error.get("code").is_some_and(|v| json_integer(v.get())) {
        return Err(bad_format(
            raw,
            r#"error["code"] is required and must be an integer value."#,
        ));
    }
    Ok(())
}

fn json_integer(text: &str) -> bool {
    matches!(text, "false" | "true")
        || text
            .trim_start_matches('-')
            .bytes()
            .all(|b| b.is_ascii_digit())
}

pub(super) fn valid_health_id(id: &RawValue, has_error: bool) -> bool {
    let raw = id.get();
    if raw == "null" {
        return has_error;
    }
    if !raw.starts_with('"') {
        return json_integer(raw);
    }
    let Ok(text) = serde_json::from_str::<String>(raw) else {
        return false;
    };
    let trimmed = text.trim();
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    digits.chars().filter(|c| *c != '_').count() <= 4300
        && digits.split('_').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| crate::unicode_decimal::decimal(c).is_some())
        })
}

fn invalid_json(body: &[u8], error: serde_json::Error) -> ReadError {
    let Ok(text) = std::str::from_utf8(body) else {
        return ReadError::Failure;
    };
    let issue = crate::request_json::json_issue(body, error);
    let offset = issue["loc"][1].as_u64().expect("JSON character offset") as usize;
    let message = issue["ctx"]["error"].as_str().expect("JSON diagnostic");
    let (line, column) =
        text.chars().take(offset).fold(
            (1, 1),
            |(l, c), ch| if ch == '\n' { (l + 1, 1) } else { (l, c + 1) },
        );
    let position = format!("line {line} column {column} (char {offset})");
    ReadError::Diagnostic(format!(
        "Could not decode {} because of {message}: {position}.: {position}",
        crate::browser_prompt::quoted_string(text)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_errors_preserve_nested_field_order_and_unbounded_integers() {
        let wide = "9".repeat(350);
        let body = format!(
            r#"{{"id":1,"error":{{"message":"offline","code":-32000,"context":{{"z":{wide},"a":[true,null]}}}},"jsonrpc":"2.0"}}"#
        );
        let Err(ReadError::Rpc(error)) = decode(body.as_bytes(), RpcRead::Contract) else {
            panic!("expected a provider failure");
        };
        assert_eq!(error.code, Some(-32000));
        assert_eq!(
            error.diagnostic,
            format!(
                "{{'message': 'offline', 'code': -32000, 'context': {{'z': {wide}, 'a': [True, None]}}}}"
            )
        );
    }

    #[test]
    fn missing_results_and_wrong_response_ids_are_rejected_but_null_is_a_result() {
        assert!(matches!(
            decode(br#"{"id":1,"jsonrpc":"2.0"}"#, RpcRead::Contract),
            Err(ReadError::Diagnostic(_))
        ));
        assert!(matches!(
            decode(
                br#"{"id":2,"jsonrpc":"2.0","result":null}"#,
                RpcRead::Contract
            ),
            Err(ReadError::Failure)
        ));
        assert!(matches!(
            decode(
                br#"{"id":1,"jsonrpc":"2.0","result":null}"#,
                RpcRead::Contract
            ),
            Ok(Value::Null)
        ));
    }

    #[test]
    fn malformed_json_reports_the_character_position_and_provider_text() {
        let Err(ReadError::Diagnostic(detail)) = decode(b"{\"jsonrpc\":", RpcRead::Contract) else {
            panic!("expected malformed response")
        };
        assert_eq!(
            detail,
            r#"Could not decode '{"jsonrpc":' because of Expecting value: line 1 column 12 (char 11).: line 1 column 12 (char 11)"#
        );
    }

    #[test]
    fn health_accepts_numeric_identifiers_and_explains_ambiguous_envelopes() {
        let input = br#"{"jsonrpc":"2.0","id":"42","result":"0x0"}"#;
        assert_eq!(
            decode(input, RpcRead::Health).unwrap(),
            Value::String("0x0".into())
        );
        assert!(matches!(
            decode(input, RpcRead::Contract),
            Err(ReadError::Failure)
        ));
        let input = br#"{"jsonrpc":"2.0","id":1,"result":null,"error":null}"#;
        assert!(
            matches!(decode(input,RpcRead::Health),Err(ReadError::Diagnostic(text)) if text.contains("cannot include both"))
        );
    }
}
