use super::*;

const FIXTURE: &str = include_str!("../../../tests/fixtures/hook-handler.wat");
fn inspect_text(source: &str) -> Result<(), String> {
    inspect(&wat::parse_str(source).unwrap())
}

#[test]
fn checks_the_version_and_full_handler_signature() {
    inspect_text(FIXTURE).unwrap();
    for (old, new) in [
        (ABI, "pyloros:hooks/handler@2.0.0"),
        ("export \"handle\"", "export \"other\""),
        ("param \"event\"", "param \"payload\""),
        ("(error string)", "(error u32)"),
    ] {
        assert!(inspect_text(&FIXTURE.replace(old, new)).is_err());
    }
}

#[test]
fn rejects_host_imports_and_validates_embedded_core_code() {
    let imported = FIXTURE.replacen("(component", "(component (import \"clock\" (func))", 1);
    assert!(
        inspect_text(&imported)
            .unwrap_err()
            .contains("host imports")
    );
    let invalid = FIXTURE.replace("i32.const 16", "f32.const 16");
    assert!(inspect_text(&invalid).is_err());
    assert!(inspect_text("(module)").is_err());
    assert!(inspect(b"not a component").is_err());
}

#[test]
fn inspection_does_not_run_guest_start_functions() {
    let trap = FIXTURE.replace(
        "(core module $guest",
        "(core module $guest (func $init unreachable) (start $init)",
    );
    inspect_text(&trap).unwrap();
}
