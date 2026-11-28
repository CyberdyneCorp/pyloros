//! Keep period integers in their wire representation until their range is checked.
use chrono::{DateTime, Datelike, Utc};
use serde::Deserialize;
use serde_json::{Value, value::RawValue};
use std::collections::BTreeMap;

type RawFields = BTreeMap<String, Box<RawValue>>;

#[derive(Deserialize)]
#[serde(try_from = "RawFields")]
pub(super) struct BillingObject {
    pub(super) current_period_end: Option<Box<RawValue>>,
    pub(super) item: Option<Item>,
    pub(super) fields: serde_json::Map<String, Value>,
}

impl TryFrom<RawFields> for BillingObject {
    type Error = serde_json::Error;

    fn try_from(mut raw: RawFields) -> Result<Self, Self::Error> {
        let current_period_end = raw.remove("current_period_end");
        let item = raw.remove("items").as_deref().and_then(first_item);
        let fields = raw
            .into_iter()
            .map(|(key, value)| serde_json::from_str(value.get()).map(|value| (key, value)))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            current_period_end,
            item,
            fields,
        })
    }
}

pub(super) struct Item {
    pub(super) price: Value,
    current_period_end: Option<Box<RawValue>>,
}

fn first_item(raw: &RawValue) -> Option<Item> {
    let items: BTreeMap<String, &RawValue> = serde_json::from_str(raw.get()).ok()?;
    let data: Vec<&RawValue> = serde_json::from_str(items.get("data")?.get()).ok()?;
    let mut fields: RawFields = serde_json::from_str(data.first()?.get()).ok()?;
    let price = fields
        .get("price")
        .and_then(|raw| serde_json::from_str(raw.get()).ok())
        .unwrap_or_default();
    Some(Item {
        price,
        current_period_end: fields.remove("current_period_end"),
    })
}

pub(super) fn expiry(
    top: Option<&RawValue>,
    item: Option<&Item>,
) -> sqlx::Result<Option<DateTime<Utc>>> {
    let selected = [
        top,
        item.and_then(|item| item.current_period_end.as_deref()),
    ]
    .into_iter()
    .flatten()
    .find_map(|raw| match raw.get() {
        "true" => Some("1"),
        "false" => Some("0"),
        number
            if number
                .strip_prefix('-')
                .unwrap_or(number)
                .bytes()
                .all(|b| b.is_ascii_digit()) =>
        {
            Some(number)
        }
        _ => None,
    });
    selected
        .map(|number| {
            number
                .parse::<i64>()
                .ok()
                .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
                .filter(|date| (1..=9999).contains(&date.year()))
                .ok_or_else(|| sqlx::Error::Protocol("invalid billing timestamp".into()))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::super::Event;

    #[test]
    fn billing_document_checks_integer_width_before_projecting_dates() {
        for (width, accepted) in [(4300, true), (4301, false)] {
            let digits = "9".repeat(width);
            let json = format!(
                r#"{{"id":"evt","type":"invoice.paid","data":{{"object":{{"current_period_end":-{digits}}}}}}}"#
            );
            let event = Event::parse(json.as_bytes());
            assert_eq!(event.is_some(), accepted);
            if let Some(event) = event {
                assert!(event.expires().is_err());
            }
        }
    }

    #[test]
    fn repeated_period_fields_use_the_last_value() {
        let json = r#"{"id":"evt","type":"invoice.paid","data":{"object":{"current_period_end":253402300800,"current_period_end":null,"items":{"data":[],"data":[{"current_period_end":253402300800,"current_period_end":12}]}}}}"#;
        let event = serde_json::from_str::<Event>(json).unwrap();
        assert_eq!(event.expires().unwrap().unwrap().timestamp(), 12);
    }

    #[test]
    fn only_the_selected_integer_controls_the_expiry() {
        for (top, item, expected) in [
            ("-62135596800", "253402300800", Some(-62135596800)),
            ("253402300799", "18446744073709551616", Some(253402300799)),
            ("253402300800.0", "12", Some(12)),
            ("1e300", "null", None),
        ] {
            let json = format!(
                r#"{{"id":"evt","type":"customer.subscription.updated","data":{{"object":{{"current_period_end":{top},"items":{{"data":[{{"current_period_end":{item}}}]}}}}}}}}"#
            );
            let event = serde_json::from_str::<Event>(&json).unwrap();
            assert_eq!(
                event.expires().unwrap().map(|date| date.timestamp()),
                expected
            );
        }
    }

    #[test]
    fn rejects_out_of_range_integer_even_when_a_fallback_exists() {
        for number in [
            "-62135596801",
            "253402300800",
            "18446744073709551616",
            "-9999999999999999999999999",
        ] {
            for (top, item) in [(number, "42"), ("null", number)] {
                let json = format!(
                    r#"{{"id":"evt","type":"invoice.paid","data":{{"object":{{"current_period_end":{top},"items":{{"data":[{{"current_period_end":{item}}}]}}}}}}}}"#
                );
                assert!(
                    serde_json::from_str::<Event>(&json)
                        .unwrap()
                        .expires()
                        .is_err()
                );
            }
        }
    }
}
