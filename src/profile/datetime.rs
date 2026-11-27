//! REST datetime fields accept timestamp strings, calendar dates and numeric epochs.
use super::*;
use chrono::{Datelike, Local, TimeZone};
use speedate::{Date, DateTime as Parsed, DateTimeConfig, MicrosecondsPrecisionOverflowBehavior};
use strum::EnumMessage;

pub(super) struct ParsedDateTime {
    pub(super) utc: DateTime<Utc>,
    pub(super) local: bool,
    offset: i32,
}

fn issue(kind: &str, message: &str, error: speedate::ParseError) -> Value {
    let reason = error
        .get_documentation()
        .expect("date parser error description");
    json!({"type":kind,"msg":format!("{message}, {reason}"),"ctx":{"error":reason}})
}

pub(super) fn parse(value: &Value) -> Result<ParsedDateTime, Value> {
    parse_with_zone(value, true)
}

pub(super) fn parse_utc(value: &Value) -> Result<ParsedDateTime, Value> {
    parse_with_zone(value, false)
}

fn parse_with_zone(value: &Value, use_local: bool) -> Result<ParsedDateTime, Value> {
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
                return expiry_value(date.timestamp(), 0, use_local, date.year, 0);
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
            return Err(json!({"type":"datetime_type","msg":"Input should be a valid datetime"}));
        }
    };
    expiry_value(
        dt.timestamp_tz(),
        dt.time.microsecond,
        dt.time.tz_offset.is_none() && use_local,
        dt.date.year,
        dt.time.tz_offset.unwrap_or(0),
    )
}

fn expiry_value(
    seconds: i64,
    micros: u32,
    local: bool,
    year: u16,
    offset: i32,
) -> Result<ParsedDateTime, Value> {
    let wall = DateTime::from_timestamp(seconds, micros * 1000).expect("parser date in range");
    if year == 0 {
        return Err(
            json!({"type":"datetime_parsing","msg":"Input should be a valid datetime, year 0 is out of range","ctx":{"error":"year 0 is out of range"}}),
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
    Ok(ParsedDateTime { utc, local, offset })
}

pub(super) const FIRST_MICROSECOND: i64 = -62_135_596_800_000_000;
pub(super) const LAST_MICROSECOND: i64 = 253_402_300_799_999_999;

impl ParsedDateTime {
    pub(super) fn audit_time(&self) -> String {
        let zone = chrono::FixedOffset::east_opt(self.offset).expect("parsed timezone offset");
        let precision = if self.utc.timestamp_subsec_micros() == 0 {
            SecondsFormat::Secs
        } else {
            SecondsFormat::Micros
        };
        self.utc
            .with_timezone(&zone)
            .to_rfc3339_opts(precision, false)
    }

    pub(super) fn database_bound(&self) -> sqlx::Result<String> {
        if self.local {
            match self
                .utc
                .with_timezone(&Local)
                .naive_local()
                .and_utc()
                .timestamp_micros()
            {
                FIRST_MICROSECOND => return Ok("-infinity".into()),
                LAST_MICROSECOND => return Ok("infinity".into()),
                _ => (),
            }
        }
        self.check_utc_year()?;
        Ok(self.utc.to_rfc3339_opts(SecondsFormat::Micros, true))
    }
    pub(super) fn check_utc_year(&self) -> sqlx::Result<()> {
        if !(1..=9999).contains(&self.utc.year()) {
            return Err(sqlx::Error::Protocol(
                "timestamp offset exceeds the supported calendar".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn year_validation_uses_the_submitted_calendar_before_applying_the_offset() {
        assert!(parse(&json!("0000-12-31T23:59:59-12:00")).is_err());
        let valid = parse(&json!("0001-01-01T00:00:00+12:00")).unwrap();
        assert!(valid.database_bound().is_err());
    }

    #[test]
    fn expires_at_retains_local_time_semantics_only_for_naive_inputs() {
        let local = parse(&json!("2030-11-01")).unwrap();
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
            let parsed = parse(&value).unwrap();
            assert!(!parsed.local);
            assert_eq!(parsed.utc.timestamp_micros(), expected);
        }
        assert!(parse(&json!("0000-01-01")).is_err());
    }
}
