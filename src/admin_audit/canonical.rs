//! Canonical JSON for audit hashes. Keep integers lossless and order object keys recursively.
use super::{Digest, Sha256, ascii};
use serde_json::value::RawValue;
use std::collections::BTreeMap;

pub(super) fn sorted_digest(value: &impl serde::Serialize) -> serde_json::Result<String> {
    let json = serde_json::to_string(value)?;
    let mut digest = Sha256::new();
    let mut cursor = 0;
    for (start, token) in crate::request_json::iam_document::unquoted_tokens(&json) {
        if token.starts_with(|c: char| c == '-' || c.is_ascii_digit())
            && token.contains(['.', 'e', 'E'])
        {
            digest.update(ascii(&json[cursor..start]));
            let n = token.parse::<f64>().expect("serialized number");
            digest.update(match n {
                f64::INFINITY => "Infinity".into(),
                f64::NEG_INFINITY => "-Infinity".into(),
                _ => crate::json_representation::float_literal(n),
            });
            cursor = start + token.len();
        }
    }
    digest.update(ascii(&json[cursor..]));
    Ok(format!("{:x}", digest.finalize()))
}

pub(crate) fn compact_metadata(
    raw: &RawValue,
    presorted: bool,
) -> serde_json::Result<Box<RawValue>> {
    let mut text = String::new();
    let fields: indexmap::IndexMap<String, &RawValue> = serde_json::from_str(raw.get())?;
    let mut fields: Vec<_> = fields.into_iter().collect();
    if !presorted {
        fields.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    }
    let mut pending = Vec::new();
    object(fields, &mut text, &mut pending);
    while let Some(part) = pending.pop() {
        match part {
            Part::Value(raw) => emit(raw, &mut text, &mut pending)?,
            Part::Key(key) => {
                text.push_str(&serde_json::to_string(&key)?);
                text.push(':');
            }
            Part::Symbol(c) => text.push(c),
        }
    }
    RawValue::from_string(text)
}

enum Part<'a> {
    Value(&'a RawValue),
    Key(String),
    Symbol(char),
}

fn emit<'a>(
    raw: &'a RawValue,
    output: &mut String,
    pending: &mut Vec<Part<'a>>,
) -> serde_json::Result<()> {
    let text = raw.get();
    match text.as_bytes()[0] {
        b'{' => {
            let fields: BTreeMap<String, &RawValue> = serde_json::from_str(text)?;
            object(fields, output, pending);
        }
        b'[' => {
            let values: Vec<&RawValue> = serde_json::from_str(text)?;
            output.push('[');
            pending.push(Part::Symbol(']'));
            for (idx, val) in values.into_iter().enumerate().rev() {
                pending.push(Part::Value(val));
                if idx > 0 {
                    pending.push(Part::Symbol(','));
                }
            }
        }
        b'"' => output.push_str(&serde_json::to_string(&serde_json::from_str::<String>(
            text,
        )?)?),
        _ => output.push_str(text),
    }
    Ok(())
}

fn object<'a>(
    fields: impl IntoIterator<
        Item = (String, &'a RawValue),
        IntoIter: DoubleEndedIterator + ExactSizeIterator,
    >,
    output: &mut String,
    pending: &mut Vec<Part<'a>>,
) {
    output.push('{');
    pending.push(Part::Symbol('}'));
    for (idx, (key, val)) in fields.into_iter().enumerate().rev() {
        pending.push(Part::Value(val));
        pending.push(Part::Key(key));
        if idx > 0 {
            pending.push(Part::Symbol(','));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_digest_preserves_large_integers_and_fractional_exponents() {
        let raw = serde_json::from_str(r#"{"text":"π", "numbers":[0.0000001, 1e16, 1844674407370955161623, 0.00001], "nested":{"z":"\n","a":["ok"]}}"#).unwrap();
        let sorted = compact_metadata(raw, false).unwrap();
        assert_eq!(
            sorted_digest(&sorted).unwrap(),
            "e2f5723f0a97ffe93ff02dcaab86f736ff7c4f9673d075e4efb0a598a6cbab25"
        );
    }
}
