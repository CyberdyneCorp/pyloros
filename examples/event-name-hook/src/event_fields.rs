//! Borrow the final matching JSON value while skipping unrelated event fields.
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::value::RawValue;
use std::fmt;

struct Field<'a>(&'a str);

impl<'de> Visitor<'de> for Field<'_> {
    type Value = Option<&'de RawValue>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON event object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut selected = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == self.0 {
                selected = Some(map.next_value()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(selected)
    }
}

pub(super) fn last_field<'a>(
    event: &'a str,
    name: &str,
) -> serde_json::Result<Option<&'a RawValue>> {
    let mut decoder = serde_json::Deserializer::from_str(event);
    let selected = decoder.deserialize_map(Field(name))?;
    decoder.end()?;
    Ok(selected)
}
