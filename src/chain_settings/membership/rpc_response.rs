//! Decode the envelope without rounding integers or reordering the provider's error.
use super::{ReadError, Value};
use serde_json::value::RawValue;
use std::collections::HashMap;

#[derive(Debug)]
pub(super) struct RpcError {
    pub(super) code: Option<i64>,
    pub(super) message: String,
    pub(super) data: Option<Box<RawValue>>,
    pub(super) diagnostic: String,
}

pub(super) fn decode(body: &[u8]) -> Result<Value, ReadError> {
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
    if version.as_deref() != Some("2.0") || fields.get("id").map(|raw| raw.get()) != Some("1") {
        return Err(ReadError::Failure);
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
    let Some(result) = fields.get("result") else {
        let rendered =
            crate::json_representation::representation(raw).map_err(|_| ReadError::Failure)?;
        return Err(ReadError::Diagnostic(format!(
            "The response was in an unexpected format and unable to be parsed. Response must include either \"error\" or \"result\". The raw response is: {rendered}"
        )));
    };
    serde_json::from_str(result.get()).map_err(|_| ReadError::Failure)
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
        let Err(ReadError::Rpc(error)) = decode(body.as_bytes()) else {
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
            decode(br#"{"id":1,"jsonrpc":"2.0"}"#),
            Err(ReadError::Diagnostic(_))
        ));
        assert!(matches!(
            decode(br#"{"id":2,"jsonrpc":"2.0","result":null}"#),
            Err(ReadError::Failure)
        ));
        assert!(matches!(
            decode(br#"{"id":1,"jsonrpc":"2.0","result":null}"#),
            Ok(Value::Null)
        ));
    }

    #[test]
    fn malformed_json_reports_the_character_position_and_provider_text() {
        let Err(ReadError::Diagnostic(detail)) = decode(b"{\"jsonrpc\":") else {
            panic!("expected malformed response")
        };
        assert_eq!(
            detail,
            r#"Could not decode '{"jsonrpc":' because of Expecting value: line 1 column 12 (char 11).: line 1 column 12 (char 11)"#
        );
    }
}
