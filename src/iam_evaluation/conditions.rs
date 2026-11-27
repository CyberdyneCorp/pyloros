use crate::unicode_decimal::decimal;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    net::{IpAddr, Ipv4Addr},
};

mod timestamp;

#[derive(Deserialize, Serialize)]
pub struct Condition {
    operator: Operator,
    key: String,
    value: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) enum Operator {
    StringEquals,
    StringNotEquals,
    NumericEquals,
    NumericLessThan,
    NumericGreaterThan,
    DateTimeLessThan,
    DateTimeGreaterThan,
    IpAddress,
    NotIpAddress,
}

#[derive(Debug, thiserror::Error)]
#[error("cannot compare timestamps with different time zone awareness")]
pub struct IncomparableTimestamps;

impl Condition {
    pub fn matches(
        &self,
        context: &std::collections::HashMap<String, String>,
    ) -> Result<bool, IncomparableTimestamps> {
        use Operator::*;
        let actual = context.get(&self.key).map(String::as_str);
        let expected = self.value.as_str();
        Ok(match self.operator {
            StringEquals => actual == Some(expected),
            StringNotEquals => actual != Some(expected),
            IpAddress => actual.is_some_and(|s| network_contains(expected, s)),
            NotIpAddress => !actual.is_some_and(|s| network_contains(expected, s)),
            NumericEquals | NumericLessThan | NumericGreaterThan => {
                let order = actual
                    .and_then(number)
                    .zip(number(expected))
                    .and_then(|(a, b)| a.partial_cmp(&b));
                matches!(
                    (&self.operator, order),
                    (NumericEquals, Some(Ordering::Equal))
                        | (NumericLessThan, Some(Ordering::Less))
                        | (NumericGreaterThan, Some(Ordering::Greater))
                )
            }
            DateTimeLessThan | DateTimeGreaterThan => {
                let order = timestamp::compare(actual, expected)?;
                matches!(
                    (&self.operator, order),
                    (DateTimeLessThan, Some(Ordering::Less))
                        | (DateTimeGreaterThan, Some(Ordering::Greater))
                )
            }
        })
    }
}

fn number(value: &str) -> Option<f64> {
    let mut result = String::new();
    let mut previous_digit = false;
    let mut pending_separator = false;
    for c in value.trim().chars() {
        let digit = decimal(c);
        if pending_separator && digit.is_none() {
            return None;
        }
        pending_separator = c == '_';
        if pending_separator {
            if !previous_digit {
                return None;
            }
        } else {
            result.push(digit.map(|n| char::from(b'0' + n as u8)).unwrap_or(c));
        }
        previous_digit = digit.is_some();
    }
    if pending_separator {
        return None;
    }
    result.parse().ok()
}

fn address(raw: &str) -> Option<IpAddr> {
    if let Some((host, zone)) = raw.split_once('%') {
        if zone.is_empty() || zone.contains(['%', '/']) {
            return None;
        }
        return host.parse().ok().map(IpAddr::V6);
    }
    raw.parse().ok()
}

fn ipv4_mask(raw: &str) -> Option<u8> {
    let bits = u32::from(raw.parse::<Ipv4Addr>().ok()?);
    let mask = if bits != 0 && bits.leading_zeros() > 0 {
        !bits
    } else {
        bits
    };
    (mask.count_ones() == mask.leading_ones()).then_some(mask.leading_ones() as u8)
}

fn network_contains(raw: &str, candidate: &str) -> bool {
    let Some(ip) = address(candidate) else {
        return false;
    };
    let (host, prefix) = raw
        .split_once('/')
        .map_or((raw, None), |(h, p)| (h, Some(p)));
    let Some(base) = address(host) else {
        return false;
    };
    let width = if base.is_ipv4() { 32 } else { 128 };
    let bits = match prefix {
        None => Some(width),
        Some(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s.parse::<u8>().ok(),
        Some(s) if base.is_ipv4() => ipv4_mask(s),
        _ => None,
    };
    bits.and_then(|n| ipnet::IpNet::new(base, n).ok())
        .is_some_and(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn check(
        op: Operator,
        limit: &str,
        actual: Option<&str>,
    ) -> Result<bool, IncomparableTimestamps> {
        let rule = Condition {
            operator: op,
            key: "v".into(),
            value: limit.into(),
        };
        let context: HashMap<_, _> = actual.into_iter().map(|s| ("v".into(), s.into())).collect();
        rule.matches(&context)
    }

    #[test]
    fn missing_keys_and_invalid_networks_follow_the_operator() {
        use Operator::*;
        assert!(check(StringNotEquals, "", None).unwrap());
        assert!(!check(StringEquals, "", None).unwrap());
        assert!(check(NotIpAddress, "::1", None).unwrap());
        assert!(check(NotIpAddress, "invalid", Some("::1")).unwrap());
        assert!(check(IpAddress, "192.0.2.42/0.0.0.255", Some("192.0.2.7")).unwrap());
        assert!(check(IpAddress, "fe80::1/64", Some("fe80::12%eth0")).unwrap());
    }

    #[test]
    fn numeric_values_accept_decimal_digits_and_compare_as_floats() {
        use Operator::*;
        assert!(check(NumericEquals, "10", Some(" １_٠ ")).unwrap());
        assert!(check(NumericGreaterThan, "1e308", Some("+Infinity")).unwrap());
        assert!(!check(NumericLessThan, "1", Some("NaN")).unwrap());
        assert!(!check(NumericEquals, "1", Some("1_")).unwrap());
    }

    #[test]
    fn timestamps_compare_at_microsecond_precision_and_preserve_awareness() {
        use Operator::*;
        assert!(check(DateTimeLessThan, "2026-01-01", Some("2026W011")).unwrap());
        assert!(
            check(
                DateTimeGreaterThan,
                "2026-02-01T01:00:00+01:00",
                Some("20260201T000000.000001Z")
            )
            .unwrap()
        );
        assert!(
            !check(
                DateTimeGreaterThan,
                "2026-02-01T00:00:00Z",
                Some("20260201T000000.0000009Z")
            )
            .unwrap()
        );
        assert!(check(DateTimeLessThan, "2026-01-01", Some("20260101T12Z")).is_err());
        assert!(!check(DateTimeLessThan, "2026-02-30", Some("20260101T12Z")).unwrap());
    }
}
