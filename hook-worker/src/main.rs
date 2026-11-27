mod source;
use serde_json::{Value, json};
use std::io::{self, Read};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimitsBuilder};

wasmtime::component::bindgen!({path: "../wit", world: "hook"});

const MAX_COMPONENT: usize = 4 << 20;
const MAX_EVENT: usize = 64 << 10;
const MAX_OUTPUT: usize = 64 << 10;

fn run(component: &[u8], event: &str) -> wasmtime::Result<Value> {
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .memory_reservation(16 << 20)
        .memory_reservation_for_growth(0)
        .memory_guard_size(64 << 10);
    let engine = Engine::new(&config)?;
    let component = Component::from_binary(&engine, component)?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(16 << 20)
        .memories(1)
        .table_elements(10_000)
        .tables(4)
        .instances(16)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(&engine, limits);
    store.limiter(|s| s);
    store.set_fuel(1_000_000)?;
    let linker = Linker::new(&engine);
    let hook = Hook::instantiate(&mut store, &component, &linker)?;
    let result = hook
        .pyloros_hooks_handler()
        .call_handle(&mut store, event)?;
    let (status, output) = match result {
        Ok(text) => ("success", text),
        Err(text) => ("error", text),
    };
    if output.len() > MAX_OUTPUT {
        return Ok(json!({"status":"failed","error":"Hook output exceeds 64 KiB"}));
    }
    Ok(json!({"status":status,"output":output}))
}

fn handle(mut input: impl Read) -> Option<Value> {
    let mut length = [0; 4];
    input.read_exact(&mut length).ok()?;
    let size = u32::from_be_bytes(length) as usize;
    if !(1..=MAX_COMPONENT).contains(&size) {
        return None;
    }
    let mut component = vec![0; size];
    input.read_exact(&mut component).ok()?;
    let mut event = String::new();
    input
        .take(MAX_EVENT as u64 + 1)
        .read_to_string(&mut event)
        .ok()?;
    if event.len() > MAX_EVENT || serde_json::from_str::<Value>(&event).is_err() {
        return None;
    }
    Some(
        run(&component, &event)
            .unwrap_or_else(|_| json!({"status":"failed","error":"Hook execution failed"})),
    )
}

#[cfg(target_os = "linux")]
fn bound_address_space() -> rustix::io::Result<()> {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    let inherited = getrlimit(Resource::As);
    let ceiling = inherited.current.unwrap_or(u64::MAX).min(1 << 30);
    setrlimit(
        Resource::As,
        Rlimit {
            current: Some(ceiling),
            maximum: Some(ceiling),
        },
    )
}

fn main() {
    #[cfg(target_os = "linux")]
    if bound_address_space().is_err() {
        std::process::exit(2);
    }
    let mut args = std::env::args_os().skip(1);
    let result = match (args.next(), args.next()) {
        (None, None) => handle(io::stdin().lock()),
        (Some(mode), None) if mode == "--parse-hook-source" => source::inspect(io::stdin().lock()),
        _ => None,
    };
    let Some(result) = result else {
        std::process::exit(2)
    };
    println!("{result}");
}

#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURE: &str = include_str!("../../tests/fixtures/hook-handler.wat");

    fn execute(body: &str, event: &str) -> wasmtime::Result<Value> {
        let module = FIXTURE.replace("i32.const 0))", &format!("{body} i32.const 0))"));
        let bytes = wat::parse_str(module).unwrap();
        run(&bytes, event)
    }

    #[test]
    fn passes_event_bytes_and_preserves_handler_errors() {
        let event = r#"{"name":"Πυλωρός","line":"a\nb"}"#;
        let echo = "i32.const 4 local.get 0 i32.store i32.const 8 local.get 1 i32.store";
        assert_eq!(
            execute(echo, event).unwrap(),
            json!({"status":"success","output":event})
        );
        let err = format!("i32.const 0 i32.const 1 i32.store8 {echo}");
        assert_eq!(
            execute(&err, event).unwrap(),
            json!({"status":"error","output":event})
        );
    }

    #[test]
    fn fuel_memory_and_output_limits_apply_independently() {
        assert!(execute("(loop $busy br $busy)", "{}").is_err());
        assert!(execute("i32.const 257 memory.grow drop", "{}").is_err());
        let oversized = "i32.const 1 memory.grow drop i32.const 8 i32.const 65537 i32.store";
        assert_eq!(execute(oversized, "{}").unwrap()["status"], "failed");
        assert_eq!(execute("", "{}").unwrap()["status"], "success");
    }

    #[test]
    fn refuses_host_imports_and_invalid_worker_frames() {
        let imported = FIXTURE.replacen("(component", "(component (import \"clock\" (func))", 1);
        assert!(run(&wat::parse_str(imported).unwrap(), "{}").is_err());
        assert!(handle(&[255u8; 4][..]).is_none());
        assert!(handle(&[0, 0, 0, 2, 0][..]).is_none());
    }
}
