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
    let fields: HashMap<String, &RawValue> =
        serde_json::from_slice(body).map_err(|_| ReadError::Failure)?;
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
    let result = fields.get("result").ok_or(ReadError::Failure)?;
    serde_json::from_str(result.get()).map_err(|_| ReadError::Failure)
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
            Err(ReadError::Failure)
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
}
