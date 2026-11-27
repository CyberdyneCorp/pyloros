//! Render JSON values with the literal formatting used in compatibility responses.
use crate::browser_prompt::quoted_string;
use serde_json::value::RawValue;

pub(crate) fn representation(raw: &RawValue) -> serde_json::Result<String> {
    // Walk the JSONB text in storage order. Rendering nested legacy values
    // needs only literal conversion, including string quoting and separators.
    let mut text = raw.get();
    let mut output = String::new();
    while !text.is_empty() {
        match text.as_bytes()[0] {
            b'{' | b'}' | b'[' | b']' => output.push(text.as_bytes()[0] as char),
            b',' => output.push_str(", "),
            b':' => output.push_str(": "),
            b'"' => {
                let mut decoder = serde_json::Deserializer::from_str(text).into_iter::<String>();
                let value = decoder.next().expect("JSON string")?;
                output.push_str(&quoted_string(&value));
                text = &text[decoder.byte_offset()..];
                continue;
            }
            byte if byte.is_ascii_whitespace() => (),
            _ => {
                let end = text
                    .find([',', ']', '}', ' ', '\n', '\r', '\t'])
                    .unwrap_or(text.len());
                output.push_str(&literal(&text[..end]));
                text = &text[end..];
                continue;
            }
        }
        text = &text[1..];
    }
    Ok(output)
}

fn literal(text: &str) -> String {
    match text {
        "null" => "None".to_owned(),
        "true" => "True".to_owned(),
        "false" => "False".to_owned(),
        number if number.contains(['.', 'e', 'E']) => {
            let number = number.parse::<f64>().expect("JSON number");
            float_literal(number)
        }
        integer => integer.to_owned(),
    }
}

pub(crate) fn float_literal(number: f64) -> String {
    if !number.is_finite() {
        return format!("{number:?}");
    }
    // Use the shortest round-to-even digits. At exponent -5 the JSON
    // formatter still uses fixed point, while the stored representation uses scientific notation.
    let rendered = serde_json::to_string(&number).expect("finite number");
    if let Some(digits) = rendered.trim_start_matches('-').strip_prefix("0.0000")
        && !digits.starts_with('0')
        && !digits.is_empty()
    {
        let (first, remaining) = digits.split_at(1);
        let sign = if number.is_sign_negative() { "-" } else { "" };
        let dot = if remaining.is_empty() { "" } else { "." };
        return format!("{sign}{first}{dot}{remaining}e-05");
    }
    match rendered.split_once('e') {
        Some((mantissa, exponent)) => format!(
            "{mantissa}e{:+03}",
            exponent.parse::<i32>().expect("float exponent")
        ),
        None => rendered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn halfway_digits_round_to_even_and_small_exponents_are_padded() {
        assert_eq!(
            float_literal(-872_554_234_916_544.0 - 0.25),
            "-872554234916544.2"
        );
        assert_eq!(float_literal(1.234e-5), "1.234e-05");
        assert_eq!(float_literal(-1e-5), "-1e-05");
    }
}
