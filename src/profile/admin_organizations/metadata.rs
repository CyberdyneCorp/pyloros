//! String projection for historical directory metadata stored in PostgreSQL JSONB.
use crate::browser_prompt::quoted_string;
use serde_json::{Value, value::RawValue};
use std::collections::BTreeMap;

pub(super) fn strings(input: &str) -> serde_json::Result<Value> {
    let raw: &RawValue = serde_json::from_str(input)?;
    let mut projected = serde_json::Map::new();
    match raw.get().as_bytes()[0] {
        b'{' => {
            let fields: BTreeMap<String, &RawValue> = serde_json::from_str(raw.get())?;
            for (key, value) in fields {
                projected.insert(key, Value::String(display(value)?));
            }
        }
        b'[' => {
            let entries: Vec<&RawValue> = serde_json::from_str(raw.get())?;
            for entry in entries {
                let (key, value) = legacy_pair(entry)?;
                projected.insert(key, Value::String(value));
            }
        }
        _ if matches!(raw.get(), "null" | "false" | "\"\"")
            || raw.get().parse::<f64>() == Ok(0.0) => {}
        _ => return Err(invalid_metadata()),
    }
    Ok(Value::Object(projected))
}

fn invalid_metadata() -> serde_json::Error {
    serde::de::Error::custom("invalid organization metadata")
}

fn legacy_pair(entry: &RawValue) -> serde_json::Result<(String, String)> {
    match entry.get().as_bytes()[0] {
        b'[' => {
            let [key, value]: [&RawValue; 2] = serde_json::from_str(entry.get())?;
            if key.get().starts_with(['[', '{']) {
                return Err(invalid_metadata());
            }
            Ok((display(key)?, display(value)?))
        }
        b'"' => {
            let word: String = serde_json::from_str(entry.get())?;
            let mut chars = word.chars();
            match (chars.next(), chars.next(), chars.next()) {
                (Some(key), Some(value), None) => Ok((key.to_string(), value.to_string())),
                _ => Err(invalid_metadata()),
            }
        }
        b'{' => {
            let fields: BTreeMap<String, &RawValue> = serde_json::from_str(entry.get())?;
            let [mut key, mut value]: [String; 2] = fields
                .into_keys()
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| invalid_metadata())?;
            if key.len() > value.len() {
                std::mem::swap(&mut key, &mut value);
            }
            Ok((key, value))
        }
        _ => Err(invalid_metadata()),
    }
}

fn display(value: &RawValue) -> serde_json::Result<String> {
    if value.get().starts_with('"') {
        serde_json::from_str(value.get())
    } else {
        representation(value)
    }
}

fn representation(raw: &RawValue) -> serde_json::Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_pairs_and_empty_values_project_to_a_directory_map() {
        assert_eq!(
            strings(r#"[["contact", "Desk"],["contact",false]]"#).unwrap(),
            serde_json::json!({"contact":"False"})
        );
        for empty in ["null", "[]", "false", "0", r#""""#] {
            assert_eq!(strings(empty).unwrap(), serde_json::json!({}));
        }
        assert!(strings("[1]").is_err());
    }

    #[test]
    fn older_metadata_preserves_nested_literals_and_integer_precision() {
        let actual = strings(r#"{"contact":"desk","values":{"a":[true,null,0.0000001,"x"],"longer":123456789012345678901}}"#).unwrap();
        assert_eq!(actual["contact"], "desk");
        assert_eq!(
            actual["values"],
            "{'a': [True, None, 1e-07, 'x'], 'longer': 123456789012345678901}"
        );
    }
}
