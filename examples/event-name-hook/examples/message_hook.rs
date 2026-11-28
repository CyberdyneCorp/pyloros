//! Emit a reviewed constant message followed by a newline.
wit_bindgen::generate!({
    path: "../../wit",
    world: "hook",
});

struct MessageHook;

impl exports::pyloros::hooks::handler::Guest for MessageHook {
    fn handle(_event: String) -> Result<String, String> {
        let message = option_env!("PYLOROS_HOOK_MESSAGE").unwrap_or("ready");
        let mut output = String::from(message);
        output.push('\n');
        if let Some((end, _)) = output.char_indices().nth(10_000) {
            output.truncate(end);
        }
        Ok(output)
    }
}

export!(MessageHook);
