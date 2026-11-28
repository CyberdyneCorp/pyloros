//! Print the successor of the numeric event field n.
use serde_json::value::RawValue;
use std::collections::BTreeMap;

wit_bindgen::generate!({
    path: "../../wit",
    world: "hook",
});

struct Counter;

impl exports::pyloros::hooks::handler::Guest for Counter {
    fn handle(event: String) -> Result<String, String> {
        let fields: BTreeMap<String, &RawValue> =
            serde_json::from_str(&event).map_err(|_| "Expected a JSON object")?;
        let value = fields.get("n").ok_or("KeyError: 'n'")?.get();
        let result = match value.as_bytes()[0] {
            b't' => "2".into(),
            b'f' => "1".into(),
            b'"' => return Err("TypeError: can only concatenate str (not \"int\") to str".into()),
            b'[' => return Err("TypeError: can only concatenate list (not \"int\") to list".into()),
            b'n' => {
                return Err(
                    "TypeError: unsupported operand type(s) for +: 'NoneType' and 'int'".into(),
                );
            }
            b'{' => {
                return Err(
                    "TypeError: unsupported operand type(s) for +: 'dict' and 'int'".into(),
                );
            }
            _ if value.contains(['.', 'e', 'E']) => {
                format_float(value.parse::<f64>().map_err(|_| "Invalid number")? + 1.0)
            }
            _ => increment_integer(value)?,
        };
        Ok(format!("{result}\n"))
    }
}

fn increment_integer(value: &str) -> Result<String, String> {
    const LIMIT: usize = 4300;
    const TOO_LARGE: &str = "ValueError: Exceeds the limit (4300 digits) for integer string conversion; use sys.set_int_max_str_digits() to increase the limit";
    let negative = value.starts_with('-');
    let mut digits = value.trim_start_matches('-').as_bytes().to_vec();
    if digits.len() > LIMIT {
        return Err(TOO_LARGE.into());
    }
    if digits == b"0" {
        return Ok("1".into());
    }
    // Adjust decimal digits in place so conversion costs stay linear under guest fuel limits.
    let (trailing, replacement) = if negative { (b'0', b'9') } else { (b'9', b'0') };
    let split = digits.iter().rposition(|&digit| digit != trailing);
    let start = split.map_or(0, |index| index + 1);
    digits[start..].fill(replacement);
    if let Some(index) = split {
        digits[index] = if negative {
            digits[index] - 1
        } else {
            digits[index] + 1
        };
    } else if digits.len() == LIMIT {
        return Err(TOO_LARGE.into());
    } else {
        digits.insert(0, b'1');
    }
    let text = String::from_utf8(digits).expect("JSON decimal digits are ASCII");
    if negative {
        let magnitude = text.trim_start_matches('0');
        return Ok(if magnitude.is_empty() {
            "0".into()
        } else {
            format!("-{magnitude}")
        });
    }
    Ok(text)
}

fn format_float(value: f64) -> String {
    if !value.is_finite() {
        return value.to_string();
    }
    let mut buffer = ryu::Buffer::new();
    let decimal = buffer.format_finite(value);
    if let Some((mantissa, exponent)) = decimal.split_once('e') {
        let exponent: i32 = exponent.parse().expect("Ryū emits a decimal exponent");
        return format!("{mantissa}e{exponent:+03}");
    }
    // Ryū uses fixed notation for exponent -5. The source runtime uses scientific notation.
    let unsigned = decimal.trim_start_matches('-');
    if let Some(digits) = unsigned.strip_prefix("0.0000") {
        let sign = if value.is_sign_negative() { "-" } else { "" };
        let (head, tail) = digits.split_at(1);
        let point = if tail.is_empty() { "" } else { "." };
        return format!("{sign}{head}{point}{tail}e-05");
    }
    decimal.to_owned()
}

export!(Counter);

#[cfg(test)]
mod tests {
    use super::{Counter, exports::pyloros::hooks::handler::Guest};

    #[test]
    fn decimal_carry_and_borrow_preserve_the_integer_limit() {
        for (input, expected) in [("-1", "0"), ("-10", "-9"), ("-0", "1"), ("99", "100")] {
            assert_eq!(
                Counter::handle(format!(r#"{{"n":{input}}}"#)).unwrap(),
                format!("{expected}\n")
            );
        }
        let digits = "9".repeat(4300);
        assert!(
            Counter::handle(format!(r#"{{"n":{digits}}}"#))
                .unwrap_err()
                .starts_with("ValueError:")
        );
    }

    #[test]
    fn numeric_types_and_error_text_survive_conversion() {
        for (input, expected) in [
            ("true", "2"),
            ("false", "1"),
            ("1.0", "2.0"),
            ("1e20", "1e+20"),
            ("1e999", "inf"),
        ] {
            assert_eq!(
                Counter::handle(format!(r#"{{"n":{input}}}"#)).unwrap(),
                format!("{expected}\n")
            );
        }
        assert_eq!(Counter::handle("{}".into()).unwrap_err(), "KeyError: 'n'");
    }
}
