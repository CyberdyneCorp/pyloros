use super::*;
use chrono::{Datelike, Local, TimeZone};
use speedate::{Date, DateTime as Parsed, DateTimeConfig, MicrosecondsPrecisionOverflowBehavior};
use strum::EnumMessage;

pub(super) const KEYS: &[&str] = &[
    "user_id",
    "organization_id",
    "product_key",
    "plan",
    "expires_at",
];

pub(super) fn parse(body: Value) -> Result<Grant, Vec<Value>> {
    let mut fields = admin_fields::Fields {
        body: admin_fields::object(&body)?,
        issues: vec![],
    };
    let user = owner(&mut fields, "user_id");
    let org = owner(&mut fields, "organization_id");
    let product = fields.string("product_key", Some(64), true);
    let plan = fields.string("plan", Some(64), false);
    let expires = fields
        .body
        .get("expires_at")
        .filter(|v| !v.is_null())
        .and_then(|v| expiry(v).map_err(|issue| fields.issues.push(issue)).ok());
    if !fields.issues.is_empty() {
        return Err(fields.issues);
    }
    Ok(Grant {
        user,
        org,
        product: product.expect("validated product"),
        plan,
        expires,
    })
}

fn owner(fields: &mut admin_fields::Fields<'_>, name: &str) -> Option<Uuid> {
    let v = fields.body.get(name).filter(|v| !v.is_null())?;
    let parsed = match v.as_str() {
        Some(s) => crate::query::uuid_field(s, "body", name),
        None => Err(
            json!({"type":"uuid_type","loc":["body",name],"msg":"UUID input should be a string, bytes or UUID object"}),
        ),
    };
    parsed.map_err(|e| fields.issues.push(e)).ok()
}

fn issue(kind: &str, message: &str, error: speedate::ParseError) -> Value {
    let reason = error
        .get_documentation()
        .expect("date parser error description");
    json!({"type":kind,"msg":format!("{message}, {reason}"),"ctx":{"error":reason},"loc":["body","expires_at"]})
}

fn expiry(value: &Value) -> Result<Expiry, Value> {
    let mut config = DateTimeConfig::default();
    config.time_config.microseconds_precision_overflow_behavior =
        MicrosecondsPrecisionOverflowBehavior::Truncate;
    config.time_config.unix_timestamp_offset = Some(0);
    let dt = match value {
        Value::String(s) => match Parsed::parse_str_with_config(s, &config) {
            Ok(date) => date,
            Err(_) => {
                let date = Date::parse_str(s).map_err(|e| {
                    issue(
                        "datetime_from_date_parsing",
                        "Input should be a valid datetime or date",
                        e,
                    )
                })?;
                return expiry_value(date.timestamp(), 0, true);
            }
        },
        Value::Number(n) => {
            let result = if let Some(i) = n.as_i64() {
                Parsed::from_timestamp_with_config(i, 0, &config)
            } else {
                let f = n.as_f64().expect("numeric input");
                let scale = if f.abs() > 20_000_000_000.0 {
                    1000.0
                } else {
                    1e6
                };
                Parsed::from_timestamp_with_config(
                    f.floor() as i64,
                    (f.abs().fract() * scale).round() as u32,
                    &config,
                )
            };
            result.map_err(|e| issue("datetime_parsing", "Input should be a valid datetime", e))?
        }
        _ => {
            return Err(
                json!({"type":"datetime_type","loc":["body","expires_at"],"msg":"Input should be a valid datetime"}),
            );
        }
    };
    expiry_value(
        dt.timestamp_tz(),
        dt.time.microsecond,
        dt.time.tz_offset.is_none(),
    )
}

fn expiry_value(seconds: i64, micros: u32, local: bool) -> Result<Expiry, Value> {
    let wall = DateTime::from_timestamp(seconds, micros * 1000).expect("parser date in range");
    if wall.year() == 0 {
        return Err(
            json!({"type":"datetime_parsing","loc":["body","expires_at"],"msg":"Input should be a valid datetime, year 0 is out of range","ctx":{"error":"year 0 is out of range"}}),
        );
    }
    let utc = if local {
        let naive = wall.naive_utc();
        // During a clock change Python selects the first occurrence or the offset before a gap.
        let offset = Local
            .offset_from_local_datetime(&naive)
            .earliest()
            .or_else(|| {
                Local
                    .offset_from_local_datetime(&(naive - chrono::Duration::days(1)))
                    .latest()
            })
            .expect("local offset around transition");
        naive.and_utc() - offset
    } else {
        wall
    };
    Ok(Expiry { utc, local })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_at_retains_local_time_semantics_only_for_naive_inputs() {
        let local = expiry(&json!("2030-11-01")).unwrap();
        assert!(local.local);
        assert_eq!(
            local.utc.with_timezone(&Local).date_naive().to_string(),
            "2030-11-01"
        );
        for (value, expected) in [
            (json!(-1.25), -1_750_000),
            (json!("-1.25"), -1_250_000),
            (json!(1.25), 1_250_000),
            (json!("1970-01-01T02:00:01.23456789+02:00"), 1_234_567),
        ] {
            let parsed = expiry(&value).unwrap();
            assert!(!parsed.local);
            assert_eq!(parsed.utc.timestamp_micros(), expected);
        }
        assert!(expiry(&json!("0000-01-01")).is_err());
    }
}
