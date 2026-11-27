//! Decode historical identity token metadata without narrowing its integer range.
use super::*;
use serde_json::value::RawValue;
use std::collections::HashMap;

#[derive(Serialize)]
struct TokenInfo<'a> {
    has_nft: bool,
    nft_token_id: Option<&'a RawValue>,
    nft_status: Option<String>,
    nft_tx_hash: Option<String>,
    nft_error: Option<String>,
    blockchain_status: Option<u8>,
}

fn token_number(raw: &RawValue) -> Option<&RawValue> {
    match raw.get() {
        "true" => Some(serde_json::from_str("1").expect("valid integer")),
        "false" => Some(serde_json::from_str("0").expect("valid integer")),
        number
            if number
                .trim_start_matches('-')
                .bytes()
                .all(|b| b.is_ascii_digit()) =>
        {
            Some(raw)
        }
        _ => None,
    }
}
pub(super) async fn response(metadata: &str, chain: Option<&Chain>) -> Response {
    let Ok(fields) = serde_json::from_str::<HashMap<String, &RawValue>>(metadata) else {
        return internal();
    };
    let id = fields.get("nft_token_id").and_then(|v| token_number(v));
    let status = if let (Some(chain), Some(id)) = (chain, id) {
        match chain.identity_status(id.get()).await {
            Ok(status) => status,
            Err(error) => return admin_client_roles::chain_error(error),
        }
    } else {
        None
    };
    let text = |key: &str| {
        fields
            .get(key)
            .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok())
    };
    let label = match status {
        Some(0) => Some("Active"),
        Some(1) => Some("Suspended"),
        Some(2) => Some("Revoked"),
        _ => None,
    };
    Json(TokenInfo {
        has_nft: id.is_some(),
        nft_token_id: id,
        nft_status: label.map(str::to_owned).or_else(|| text("nft_status")),
        nft_tx_hash: text("nft_tx_hash"),
        nft_error: text("nft_error"),
        blockchain_status: status,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_token_ids_keep_precision_and_preserve_legacy_booleans() {
        for (input, expected) in [
            (
                "1208925819614629174706177",
                Some("1208925819614629174706177"),
            ),
            ("false", Some("0")),
            ("true", Some("1")),
            ("-1", Some("-1")),
            ("1.25", None),
            ("null", None),
            (r#""123""#, None),
        ] {
            let raw: &RawValue = serde_json::from_str(input).unwrap();
            assert_eq!(token_number(raw).map(RawValue::get), expected);
        }
    }
}
