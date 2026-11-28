//! Decode provider quantities without losing JSON integer precision.
use super::*;

// Keep numeric quantities in their original JSON representation until they have
// been parsed into 256 bits. serde_json::Value alone rounds large JSON numbers.
#[derive(Deserialize, serde::Serialize)]
#[serde(try_from = "Box<serde_json::value::RawValue>")]
struct RpcQuantity(TokenId);

impl TryFrom<Box<serde_json::value::RawValue>> for RpcQuantity {
    type Error = &'static str;

    fn try_from(raw: Box<serde_json::value::RawValue>) -> Result<Self, Self::Error> {
        let invalid = "invalid unsigned transaction quantity";
        if raw.get().starts_with('"') {
            let text: String = serde_json::from_str(raw.get()).map_err(|_| invalid)?;
            let hex = text
                .strip_prefix("0x")
                .or_else(|| text.strip_prefix("0X"))
                .unwrap_or(&text);
            if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid);
            }
            TokenId::from_str_radix(hex, 16)
                .map(Self)
                .map_err(|_| invalid)
        } else if raw.get().bytes().all(|b| b.is_ascii_digit()) {
            TokenId::from_str_radix(raw.get(), 10)
                .map(Self)
                .map_err(|_| invalid)
        } else {
            Err(invalid)
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::chain_settings::membership) enum QuantityResult {
    Scalar,
    Block,
    History,
}

impl QuantityResult {
    pub(in crate::chain_settings::membership) fn decode(
        self,
        raw: &serde_json::value::RawValue,
    ) -> Result<Value, ReadError> {
        #[derive(Deserialize)]
        struct Block {
            #[serde(rename = "baseFeePerGas")]
            fee: RpcQuantity,
        }
        #[derive(Deserialize)]
        struct History {
            reward: Vec<Vec<RpcQuantity>>,
        }
        match self {
            Self::Scalar => serde_json::from_str::<RpcQuantity>(raw.get()).map(|fee| json!(fee.0)),
            Self::Block => serde_json::from_str::<Block>(raw.get()).map(|block| json!(block.fee.0)),
            Self::History => serde_json::from_str::<History>(raw.get())
                .map(|history| json!({"reward": history.reward})),
        }
        .map_err(|_| ReadError::Failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::value::RawValue;

    fn parse(wire: &str) -> Result<TokenId, ReadError> {
        let raw: &RawValue = serde_json::from_str(wire).unwrap();
        let value = QuantityResult::Scalar.decode(raw)?;
        TokenId::deserialize(value).map_err(|_| ReadError::Failure)
    }

    #[test]
    fn normalizes_hex_strings_and_exact_decimal_integers() {
        for wire in [r#""0x11""#, r#""0X11""#, r#""11""#, "17"] {
            assert_eq!(parse(wire).unwrap(), TokenId::from(17));
        }
        let maximum = TokenId::MAX.to_string();
        assert_eq!(parse(&maximum).unwrap(), TokenId::MAX);
        for invalid in [
            "-1",
            "1.0",
            "1e3",
            "true",
            "null",
            r#""0x""#,
            &format!("{maximum}0"),
        ] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
    }
}
