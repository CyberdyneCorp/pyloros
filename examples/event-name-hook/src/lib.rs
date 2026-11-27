//! Record the type of the event without disclosing its other fields.
wit_bindgen::generate!({
    path: "../../wit",
    world: "hook",
});

struct EventName;

impl exports::pyloros::hooks::handler::Guest for EventName {
    fn handle(event: String) -> Result<String, String> {
        let context: serde_json::Value =
            serde_json::from_str(&event).map_err(|_| "Expected a JSON event".to_owned())?;
        let name = context["event_type"]
            .as_str()
            .ok_or_else(|| "ValueError: Expected an event_type string".to_owned())?;
        Ok(format!("{name}\n"))
    }
}

export!(EventName);
