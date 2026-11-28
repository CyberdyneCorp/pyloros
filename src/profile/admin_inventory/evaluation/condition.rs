//! Evaluate historical JSONB condition operands after a statement's targets match.
use crate::iam_evaluation::Operator;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Deserialize)]
pub(super) struct StoredCondition {
    operator: Operator,
    key: Box<RawValue>,
    value: Box<RawValue>,
}

fn text(raw: &str) -> sqlx::Result<String> {
    serde_json::from_str(raw).map_err(|e| sqlx::Error::Decode(e.into()))
}

impl StoredCondition {
    pub(super) fn matches(&self, context: &HashMap<String, String>) -> sqlx::Result<bool> {
        let key = self.key.get();
        let actual = match key.as_bytes()[0] {
            b'{' | b'[' => return Err(sqlx::Error::Decode("unhashable IAM condition key".into())),
            b'"' => context.get(&text(key)?).map(String::as_str),
            _ => None,
        };
        let raw = self.value.get();
        if raw.starts_with('"') {
            return self.compare(actual, &text(raw)?);
        }
        use Operator::*;
        match self.operator {
            StringEquals | DateTimeLessThan | DateTimeGreaterThan => Ok(false),
            StringNotEquals => Ok(true),
            NumericEquals | NumericLessThan | NumericGreaterThan => {
                let Some(value) = numeric(raw)? else {
                    return Ok(false);
                };
                self.compare(actual, value)
            }
            IpAddress | NotIpAddress => match integer_address(raw) {
                Some(host) => self.compare(actual, &host),
                None => Ok(matches!(self.operator, NotIpAddress)),
            },
        }
    }

    fn compare(&self, actual: Option<&str>, expected: &str) -> sqlx::Result<bool> {
        self.operator
            .matches_text(actual, expected)
            .map_err(|e| sqlx::Error::Decode(e.into()))
    }
}

fn scalar_number(raw: &str) -> Option<&str> {
    match raw {
        "true" => Some("1"),
        "false" => Some("0"),
        _ if raw.starts_with(|c: char| c == '-' || c.is_ascii_digit()) => Some(raw),
        _ => None,
    }
}

fn numeric(raw: &str) -> sqlx::Result<Option<&str>> {
    let Some(value) = scalar_number(raw) else {
        return Ok(None);
    };
    if !value.contains(['.', 'e', 'E']) && value.parse::<f64>().is_ok_and(|n| !n.is_finite()) {
        return Err(sqlx::Error::Decode(
            "IAM condition integer exceeds floating-point range".into(),
        ));
    }
    Ok(Some(value))
}

fn integer_address(raw: &str) -> Option<String> {
    let n: u128 = scalar_number(raw)?.parse().ok()?;
    Some(match u32::try_from(n) {
        Ok(v4) => Ipv4Addr::from(v4).to_string(),
        Err(_) => Ipv6Addr::from(n).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_and_string_operators_preserve_historical_operand_types() {
        let context = HashMap::from([("limit".into(), "7".into())]);
        for (operator, expected) in [
            ("NumericEquals", true),
            ("StringEquals", false),
            ("StringNotEquals", true),
        ] {
            let condition: StoredCondition = serde_json::from_str(&format!(
                r#"{{"operator":"{operator}","key":"limit","value":7}}"#
            ))
            .unwrap();
            assert_eq!(condition.matches(&context).unwrap(), expected);
        }
        assert!(numeric(&"9".repeat(310)).is_err());
        assert_eq!(integer_address("true").as_deref(), Some("0.0.0.1"));
        assert!(integer_address("1.0").is_none());
    }
}
