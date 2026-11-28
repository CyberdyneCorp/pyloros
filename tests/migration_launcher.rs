#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn migration_launcher_resolves_packaged_assets_and_preserves_overrides() {
    let staging = tempfile::tempdir().unwrap();
    let package = staging.path().canonicalize().unwrap().join("moved release");
    fs::create_dir(&package).unwrap();
    let launcher = package.join("pyloros-migration");
    fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/pyloros-migration"),
        &launcher,
    )
    .unwrap();
    let binary = package.join("pyloros");
    fs::write(&binary, r#"#!/bin/sh
printf '%s\n' "$PYLOROS_SIGNED_OUT_HTML_PATH" "$PYLOROS_CONSENT_UI_PATH" "$PYLOROS_DEVICE_UI_PATH" "$PYLOROS_ERASURE_REPORT_PATH" "$PYLOROS_OPENAPI_PATH" "$PYLOROS_OPENAPI_CSP" "${PYLOROS_REGISTRATION_TIME_ZONE-unset}" "$@"
"#).unwrap();
    fs::set_permissions(binary, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        package.join("migration-openapi.csp"),
        "default-src 'none'\n",
    )
    .unwrap();

    let mut cmd = Command::new(launcher);
    cmd.env_clear()
        .current_dir(staging.path())
        .arg("argument with spaces");
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let mut expected: Vec<String> = [
        "signed-out.html",
        "consent-ui.json",
        "device-ui.json",
        "erasure-report.json",
        "migration-openapi.json",
    ]
    .map(|name| package.join(name).to_str().unwrap().to_owned())
    .into();
    expected.extend([
        "default-src 'none'".to_owned(),
        "unset".to_owned(),
        "argument with spaces".to_owned(),
    ]);
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        expected
    );

    fs::write(package.join("registration-time-zone"), "\n").unwrap();
    assert!(!cmd.output().unwrap().status.success());
    fs::write(package.join("registration-time-zone"), "America/Barbados\n").unwrap();
    let calendar = cmd.output().unwrap();
    assert!(calendar.status.success());
    assert_eq!(
        String::from_utf8(calendar.stdout).unwrap().lines().nth(6),
        Some("America/Barbados")
    );

    fs::remove_file(package.join("migration-openapi.csp")).unwrap();
    assert!(!cmd.output().unwrap().status.success());
    cmd.env("PYLOROS_SIGNED_OUT_HTML_PATH", "/alternate/page.html")
        .env("PYLOROS_OPENAPI_CSP", "custom policy")
        .env("PYLOROS_REGISTRATION_TIME_ZONE", "Asia/Kathmandu");
    expected[6] = "Asia/Kathmandu".into();
    expected[0] = "/alternate/page.html".into();
    expected[5] = "custom policy".into();
    let overridden = cmd.output().unwrap();
    assert!(overridden.status.success());
    assert_eq!(
        String::from_utf8(overridden.stdout)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        expected
    );
}
