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
            let rendered = format!("{number:?}");
            match rendered.split_once('e') {
                Some((mantissa, exponent)) => format!(
                    "{mantissa}e{:+03}",
                    exponent.parse::<i32>().expect("float exponent")
                ),
                None => rendered,
            }
        }
        integer => integer.to_owned(),
    }
}
