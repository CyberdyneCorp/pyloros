use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
mod time;

pub(super) struct Cursor {
    pub at: DateTime<Utc>,
    pub id: Uuid,
}

impl Cursor {
    pub(super) fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(format!(
            "v1|{}|{}",
            self.at.format("%Y-%m-%dT%H:%M:%S%.6f"),
            self.id
        ))
    }

    pub(super) fn decode(text: &str) -> Option<Self> {
        if !text.is_ascii() {
            return None;
        }
        let mut padded = text.replace('-', "+").replace('_', "/");
        padded.extend(std::iter::repeat_n('=', (4 - text.len() % 4) % 4));
        let mut input = Vec::new();
        let mut padding = 0;
        for b in padded.bytes() {
            if b == b'=' {
                padding += 1;
                if input.len() % 4 >= 2 && input.len() % 4 + padding >= 4 {
                    break;
                }
            } else if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/') {
                input.push(b);
                padding = 0;
            }
        }
        if input.len() % 4 != 0 && input.len() % 4 + padding != 4 {
            return None;
        }
        let engine = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::general_purpose::NO_PAD.with_decode_allow_trailing_bits(true),
        );
        let decoded = String::from_utf8(engine.decode(input).ok()?).ok()?;
        let mut fields = decoded.split('|');
        if fields.next()? != "v1" {
            return None;
        }
        let stamp = fields.next()?;
        let at = time::parse(stamp)?.and_utc();
        let hex = fields.next()?.replace("urn:", "").replace("uuid:", "");
        let hex = hex.trim_matches(['{', '}']).replace('-', "");
        if hex.chars().count() != 32 {
            return None;
        }
        let digits = crate::unicode_decimal::hexadecimal_magnitude(&hex)?;
        let id = Uuid::from_u128(u128::from_str_radix(&digits, 16).ok()?);
        fields.next().is_none().then_some(Self { at, id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_preserves_microseconds_and_identifier() {
        let at = DateTime::parse_from_rfc3339("2026-05-03T18:43:25.000003Z")
            .unwrap()
            .to_utc();
        let cursor = Cursor {
            at,
            id: Uuid::from_u128(193),
        };
        let decoded = Cursor::decode(&cursor.encode()).unwrap();
        assert_eq!((decoded.at, decoded.id), (at, cursor.id));
    }

    #[test]
    fn cursor_identifier_uses_hexadecimal_integer_syntax() {
        for suffix in ["０a", "+a", "0_a", "0x_a", "＿a", "__a"] {
            let hex = format!("{}{}", "0".repeat(32 - suffix.chars().count()), suffix);
            let wrapped = URL_SAFE_NO_PAD.encode(format!("v1|2026-02-09|{hex}"));
            let value = Cursor::decode(&wrapped).map(|c| c.id.as_u128());
            assert_eq!(
                value,
                match suffix {
                    "０a" | "0_a" => Some(10),
                    _ => None,
                }
            );
        }
        for prefix in ["+", "0x_", " "] {
            let hex = format!("{prefix}{}a", "0".repeat(31 - prefix.len()));
            let wrapped = URL_SAFE_NO_PAD.encode(format!("v1|2026-02-09|{hex}"));
            assert_eq!(Cursor::decode(&wrapped).unwrap().id.as_u128(), 10);
        }
    }

    #[test]
    fn offset_cursor_preserves_stored_wall_time() {
        let text = format!("v1|2026-05-03T18:43:25+04:00|{}", Uuid::nil());
        let decoded = Cursor::decode(&URL_SAFE_NO_PAD.encode(text)).unwrap();
        assert_eq!(decoded.at.to_rfc3339(), "2026-05-03T18:43:25+00:00");
    }
}
