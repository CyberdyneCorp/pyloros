//! String projection for historical directory metadata stored in PostgreSQL JSONB.
use crate::json_representation::representation;
use serde_json::{Value, value::RawValue};
use std::collections::BTreeMap;

pub(super) fn strings(input: &str) -> serde_json::Result<Value> {
    crate::stored_json::check_integers(input).map_err(serde::de::Error::custom)?;
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
            for entry in legacy_entries(raw)?.into_values() {
                projected.insert(entry.display_key, Value::String(display(&entry.value)?));
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

pub(crate) fn normalized_storage(input: &str) -> Result<Option<String>, sqlx::Error> {
    crate::stored_json::check_integers(input)?;
    if input.starts_with('{') {
        return Ok(None);
    }
    stored_object(input)
        .map(Some)
        .map_err(|e| sqlx::Error::Decode(e.into()))
}

// Writing an old list of pairs back to JSONB preserves the value types.
// Displaying the same map converts values to strings instead.
fn stored_object(input: &str) -> serde_json::Result<String> {
    if !input.starts_with('[') {
        return if matches!(input, "null" | "false" | "\"\"") || input.parse::<f64>() == Ok(0.0) {
            Ok("{}".into())
        } else {
            Err(invalid_metadata())
        };
    }
    let entries = legacy_entries(serde_json::from_str(input)?)?;
    let fields: BTreeMap<_, _> = entries
        .into_values()
        .map(|entry| (entry.json_key, entry.value))
        .collect();
    serde_json::to_string(&fields)
}

struct Entry {
    json_key: String,
    display_key: String,
    value: Box<RawValue>,
}

// Historical pair lists can contain non-string keys. Their original types determine
// comparison order before JSON encodes the keys as strings.
pub(crate) fn audit_object(raw: &str, sorted: bool) -> sqlx::Result<Option<String>> {
    if !raw.starts_with('[') {
        return normalized_storage(raw);
    }
    let mut fields = serde_json::from_str(raw)
        .and_then(legacy_entries)
        .map_err(|e| sqlx::Error::Decode(e.into()))?;
    if sorted {
        if let Some(((kind, _), _)) = fields.first()
            && fields.keys().any(|(k, _)| k != kind)
        {
            return Err(sqlx::Error::Decode(
                "incomparable audit metadata keys".into(),
            ));
        }
        fields.sort_by(|(kind, a), _, (_, b), _| {
            if *kind == 'n' {
                compare_numbers(a, b)
            } else {
                a.cmp(b)
            }
        });
    }
    // Distinct historical keys can have the same JSON string spelling.
    // Serialize each entry directly to preserve both in the downloaded file.
    let mut bytes = Vec::new();
    let mut serializer = serde_json::Serializer::new(&mut bytes);
    use serde::ser::{SerializeMap, Serializer};
    let mut map = serializer
        .serialize_map(Some(fields.len()))
        .map_err(|e| sqlx::Error::Encode(e.into()))?;
    for ((kind, _), f) in fields {
        let key = match (kind, f.json_key.as_str()) {
            ('n', "inf") => "Infinity".into(),
            ('n', "-inf") => "-Infinity".into(),
            _ => f.json_key,
        };
        map.serialize_entry(&key, &f.value)
            .map_err(|e| sqlx::Error::Encode(e.into()))?;
    }
    map.end().map_err(|e| sqlx::Error::Encode(e.into()))?;
    Ok(Some(String::from_utf8(bytes).expect("JSON is UTF-8")))
}

fn compare_numbers(a: &str, b: &str) -> std::cmp::Ordering {
    // Fractional binary64 values and exact integers can only tie after conversion
    // at integral magnitudes. Break those ties with the exact decimal digits.
    let order = a
        .parse::<f64>()
        .expect("numeric key")
        .total_cmp(&b.parse::<f64>().expect("numeric key"));
    if !order.is_eq() {
        return order;
    }
    let magnitude = |v: &str| {
        if v == "inf" || v == "-inf" {
            usize::MAX
        } else {
            v.len()
        }
    };
    let exact = magnitude(a).cmp(&magnitude(b)).then_with(|| a.cmp(b));
    if a.starts_with('-') {
        exact.reverse()
    } else {
        exact
    }
}

type Entries = indexmap::IndexMap<(char, String), Entry>;

fn legacy_entries(raw: &RawValue) -> serde_json::Result<Entries> {
    let pairs: Vec<&RawValue> = serde_json::from_str(raw.get())?;
    let mut entries = indexmap::IndexMap::new();
    for pair in pairs {
        let (key, value) = legacy_pair(pair)?;
        let rendered = display(&key)?;
        let (identity, json_key) = key_identity(&key, &rendered);
        // Equivalent numeric keys overwrite the value and keep the first key.
        entries
            .entry(identity)
            .and_modify(|entry: &mut Entry| entry.value = value.clone())
            .or_insert(Entry {
                json_key,
                display_key: rendered,
                value,
            });
    }
    Ok(entries)
}

fn key_identity(key: &RawValue, rendered: &str) -> ((char, String), String) {
    let text = key.get();
    let (kind, id) = match text {
        "true" => ('n', "1".into()),
        "false" => ('n', "0".into()),
        "null" => ('z', String::new()),
        _ if text.starts_with('"') => ('s', rendered.to_owned()),
        _ if text.contains(['.', 'e', 'E']) => {
            let n = text.parse::<f64>().expect("JSON number");
            let identity = if n == 0.0 {
                "0".into()
            } else if n.fract() == 0.0 {
                format!("{n:.0}")
            } else {
                rendered.to_owned()
            };
            ('n', identity)
        }
        _ => ('n', text.to_owned()),
    };
    let json_key = if matches!(text, "true" | "false" | "null") {
        text
    } else {
        rendered
    };
    ((kind, id), json_key.to_owned())
}

fn legacy_pair(entry: &RawValue) -> serde_json::Result<(Box<RawValue>, Box<RawValue>)> {
    let pair = match entry.get().as_bytes()[0] {
        b'[' => {
            let [key, value]: [&RawValue; 2] = serde_json::from_str(entry.get())?;
            if key.get().starts_with(['[', '{']) {
                return Err(invalid_metadata());
            }
            return Ok((key.to_owned(), value.to_owned()));
        }
        b'"' => {
            let word: String = serde_json::from_str(entry.get())?;
            let mut chars = word.chars();
            match (chars.next(), chars.next(), chars.next()) {
                (Some(key), Some(value), None) => (key.to_string(), value.to_string()),
                _ => return Err(invalid_metadata()),
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
            (key, value)
        }
        _ => return Err(invalid_metadata()),
    };
    Ok((
        serde_json::value::to_raw_value(&pair.0)?,
        serde_json::value::to_raw_value(&pair.1)?,
    ))
}

fn display(value: &RawValue) -> serde_json::Result<String> {
    if value.get().starts_with('"') {
        serde_json::from_str(value.get())
    } else {
        representation(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_rejects_oversized_integers_before_stringifying_values() {
        let n = "9".repeat(4301);
        assert!(strings(&format!(r#"{{"nested":[{n}]}}"#)).is_err());
        assert!(strings(&format!(r#"[["key",{n}],["key","new"]]"#)).is_err());
        assert_eq!(strings(&format!(r#"{{"key":"{n}"}}"#)).unwrap()["key"], n);
    }

    #[test]
    fn check_integer_width_before_projecting_or_replacing_metadata_fields() {
        let limit = "8".repeat(4300);
        assert!(normalized_storage(&format!(r#"{{"old":[{limit}]}}"#)).is_ok());
        assert!(normalized_storage(&format!(r#"{{"old":[{limit}8]}}"#)).is_err());
        assert!(normalized_storage(&format!(r#"[["old",-{limit}8],["old",0]]"#)).is_err());
        assert!(normalized_storage(&format!(r#"{{"old":"{limit}8"}}"#)).is_ok());
    }

    #[test]
    fn membership_reads_reject_invalid_metadata_and_preserve_legacy_values_on_write() {
        assert!(normalized_storage("true").is_err());
        assert!(normalized_storage("[[1]]").is_err());
        assert_eq!(normalized_storage("null").unwrap().as_deref(), Some("{}"));
        assert_eq!(normalized_storage(r#"{"tier":3}"#).unwrap(), None);
        assert_eq!(
            normalized_storage(r#"[["tier",3]]"#).unwrap().as_deref(),
            Some(r#"{"tier":3}"#)
        );
    }

    #[test]
    fn pair_keys_keep_the_first_equivalent_numeric_key_and_the_last_value() {
        let input = r#"[[1,"old"],[true,42],[null,["nested",false]]]"#;
        assert_eq!(
            stored_object(input).unwrap(),
            r#"{"1":42,"null":["nested",false]}"#
        );
        assert_eq!(
            strings(input).unwrap(),
            serde_json::json!({"1":"42","None":"['nested', False]"})
        );
    }

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
