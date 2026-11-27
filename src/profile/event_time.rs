//! Decode the full PostgreSQL timestamp range before projecting it into the REST calendar.
use super::*;
use sqlx::{Row, postgres::PgRow};

pub(super) struct EventTime {
    pub(super) utc: DateTime<Utc>,
    infinity: bool,
}

impl EventTime {
    pub(super) fn read(row: &PgRow) -> sqlx::Result<Self> {
        let bytes: &[u8] = row.try_get("event_time")?;
        Self::decode(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> sqlx::Result<Self> {
        let value = i64::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| sqlx::Error::Protocol("invalid binary timestamp".into()))?,
        );
        Self::from_postgres(value)
    }

    fn from_postgres(value: i64) -> sqlx::Result<Self> {
        const UNIX_TO_PG_MICROS: i64 = 946_684_800_000_000;
        let (micros, infinity) = match value {
            i64::MIN => (datetime::FIRST_MICROSECOND, true),
            i64::MAX => (datetime::LAST_MICROSECOND, true),
            finite => (finite.saturating_add(UNIX_TO_PG_MICROS), false),
        };
        if !(datetime::FIRST_MICROSECOND..=datetime::LAST_MICROSECOND).contains(&micros) {
            return Err(sqlx::Error::Decode(
                "audit time exceeds the supported calendar".into(),
            ));
        }
        Ok(Self {
            utc: DateTime::from_timestamp_micros(micros).expect("calendar year 1 through 9999"),
            infinity,
        })
    }

    pub(super) fn display(&self, suffix: &str) -> String {
        let mut value = timestamp(self.utc);
        value.pop(); // UTC marker
        if !self.infinity {
            value.push_str(suffix);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn infinity_uses_the_calendar_limits_without_a_timezone() {
        assert_eq!(
            EventTime::from_postgres(i64::MIN).unwrap().display("Z"),
            "0001-01-01T00:00:00"
        );
        assert_eq!(
            EventTime::from_postgres(i64::MAX)
                .unwrap()
                .display("+00:00"),
            "9999-12-31T23:59:59.999999"
        );
        assert!(EventTime::from_postgres(i64::MAX - 1).is_err());
    }
}
