#![cfg(unix)]

use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn every_case_uses_the_artifact_read_at_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let wasm = wat::parse_str(include_str!("fixtures/hook-handler.wat")).unwrap();
    let worker = path.join("worker");
    fs::write(
        &worker,
        r#"#!/bin/sh
set -eu
cd "$(dirname "$0")"
cat > frame
if test -e first; then
    cmp -s frame first
else
    cp frame first
    echo replaced > component
fi
echo '{"status":"success","output":"private sample"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path.join("event"), r#"{"tag":"private event"}"#).unwrap();
    fs::write(
        path.join("match"),
        r#"{"status":"success","output":"private sample"}"#,
    )
    .unwrap();
    fs::write(
        path.join("mismatch"),
        r#"{"status":"success","output":"private expectation"}"#,
    )
    .unwrap();

    let run = |last: &str| {
        fs::write(path.join("component"), &wasm).unwrap();
        Command::new(env!("CARGO_BIN_EXE_pyloros"))
            .current_dir(path)
            .env_remove("DATABASE_URL")
            .env("PYLOROS_HOOK_WORKER", &worker)
            .args([
                "--check-hook-fixture",
                "component",
                "event",
                "match",
                "event",
                last,
            ])
            .output()
            .unwrap()
    };
    let ok = run("match");
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(
        String::from_utf8(ok.stdout).unwrap(),
        format!("{:x}\n", Sha256::digest(&wasm))
    );
    fs::remove_file(path.join("first")).unwrap();
    let failed = run("mismatch");
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    let error = String::from_utf8(failed.stderr).unwrap();
    assert!(error.contains("Fixture 2"));
    assert!(!error.contains("private"));
}

#[test]
fn incomplete_pair_is_rejected_before_loading_the_component() {
    let result = Command::new(env!("CARGO_BIN_EXE_pyloros"))
        .env_remove("DATABASE_URL")
        .args(["--check-hook-fixture", "absent-component", "unpaired-event"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("each event must have an expected outcome path")
    );
}
