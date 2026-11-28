//! Complete an event without emitting output.
wit_bindgen::generate!({
    path: "../../wit",
    world: "hook",
});

struct SilentHook;

impl exports::pyloros::hooks::handler::Guest for SilentHook {
    fn handle(_event: String) -> Result<String, String> {
        Ok(String::new())
    }
}

export!(SilentHook);
