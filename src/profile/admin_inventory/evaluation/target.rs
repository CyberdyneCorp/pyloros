//! Historical target entries are interpreted only when matching reaches them.
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use std::collections::HashMap;

pub(super) enum Target {
    Pattern(String),
    Never,
    Invalid,
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(d)?;
        decode(raw.get()).map_err(serde::de::Error::custom)
    }
}

fn decode(raw: &str) -> serde_json::Result<Target> {
    match raw.as_bytes()[0] {
        b'"' => serde_json::from_str(raw).map(Target::Pattern),
        b'[' => sequence(raw),
        b'{' => {
            let keys: HashMap<String, &RawValue> = serde_json::from_str(raw)?;
            Ok(if keys.contains_key("*") {
                Target::Invalid
            } else {
                Target::Never
            })
        }
        _ => Ok(Target::Invalid),
    }
}

fn sequence(raw: &str) -> serde_json::Result<Target> {
    let entries: Vec<&RawValue> = serde_json::from_str(raw)?;
    let mut pattern = String::new();
    for entry in entries {
        let Ok(text) = serde_json::from_str::<String>(entry.get()) else {
            return Ok(Target::Never);
        };
        if text.chars().count() != 1 {
            return Ok(Target::Never);
        }
        pattern.push_str(&text);
    }
    Ok(if pattern.contains('*') {
        Target::Pattern(pattern)
    } else {
        Target::Never
    })
}

pub(super) fn any(targets: &[Target], value: &str) -> sqlx::Result<bool> {
    for target in targets {
        match target {
            Target::Pattern(p) if crate::iam_evaluation::matches_pattern(p, value) => {
                return Ok(true);
            }
            Target::Invalid => return Err(sqlx::Error::Decode("invalid stored IAM target".into())),
            _ => {}
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_order_controls_whether_an_invalid_entry_is_reached() {
        for (raw, expected) in [
            (r#"["read",17]"#, Some(true)),
            (r#"[17,"read"]"#, None),
            (r#"[["r","*","d"]]"#, Some(true)),
            (r#"[["r","e","a","d"]]"#, Some(false)),
            (r#"[["re","*","d"]]"#, Some(false)),
            (r#"[{"*":1}]"#, None),
            (r#"[{"r":1},"read"]"#, Some(true)),
        ] {
            let targets: Vec<Target> = serde_json::from_str(raw).unwrap();
            assert_eq!(any(&targets, "read").ok(), expected, "{raw}");
        }
    }
}
