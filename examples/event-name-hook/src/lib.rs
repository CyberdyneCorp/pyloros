//! Record the type of the event without disclosing its other fields.
wit_bindgen::generate!({
    path: "../../wit",
    world: "hook",
});

struct EventName;

impl exports::pyloros::hooks::handler::Guest for EventName {
    fn handle(event: String) -> Result<String, String> {
        use serde_json::value::RawValue;
        use std::collections::BTreeMap;

        let invalid = |_| "Expected a JSON event".to_owned();
        let missing = || "ValueError: Expected an event_type string".to_owned();
        if !event.trim_start().starts_with('{') {
            serde_json::from_str::<&RawValue>(&event).map_err(invalid)?;
            return Err(missing());
        }
        // Borrow field values so unrelated arrays never become guest allocations.
        let fields: BTreeMap<String, &RawValue> = serde_json::from_str(&event).map_err(invalid)?;
        let raw = fields.get("event_type").ok_or_else(missing)?;
        let mut name: String = serde_json::from_str(raw.get()).map_err(|_| missing())?;
        name.push('\n');
        if let Some((end, _)) = name.char_indices().nth(10_000) {
            name.truncate(end);
        }
        Ok(name)
    }
}

export!(EventName);

#[cfg(test)]
mod tests {
    use super::{EventName, exports::pyloros::hooks::handler::Guest};

    #[test]
    fn counts_the_newline_and_each_unicode_scalar_toward_the_output_limit() {
        let prefix = "雪".repeat(9_999);
        for (name, last) in [(prefix.clone(), "\n"), (format!("{prefix}e\u{301}"), "e")] {
            let event = serde_json::json!({"event_type": name}).to_string();
            assert_eq!(EventName::handle(event).unwrap(), format!("{prefix}{last}"));
        }
    }

    #[test]
    fn reads_the_final_decoded_field_and_preserves_errors() {
        let context = r#"{"event_type":null,"other":[{},[]],"event_\u0074ype":"a\nb"}"#;
        assert_eq!(EventName::handle(context.into()).unwrap(), "a\nb\n");
        for input in ["null", "[]", "{}", r#"{"event_type":false}"#] {
            assert_eq!(
                EventName::handle(input.into()).unwrap_err(),
                "ValueError: Expected an event_type string"
            );
        }
        assert_eq!(
            EventName::handle("[".into()).unwrap_err(),
            "Expected a JSON event"
        );
    }
}
