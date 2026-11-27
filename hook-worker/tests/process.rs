use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn packaged_worker_reads_one_frame_with_runtime_limits_enabled() {
    let wasm = wat::parse_str(include_str!("../../tests/fixtures/hook-handler.wat")).unwrap();
    let mut worker = Command::new(env!("CARGO_BIN_EXE_pyloros-hook-worker"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = worker.stdin.take().unwrap();
    input.write_all(&(wasm.len() as u32).to_be_bytes()).unwrap();
    input.write_all(&wasm).unwrap();
    input.write_all(b"{}").unwrap();
    drop(input);
    let output = worker.wait_with_output().unwrap();
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result, serde_json::json!({"status":"success","output":""}));
}
