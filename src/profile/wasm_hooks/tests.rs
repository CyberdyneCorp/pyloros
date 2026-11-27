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

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn artifact_table_checks_content_identity_and_upload_bounds() {
    let pool = sqlx::PgPool::connect(&env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let ddl = include_str!("../../../migrations/001_hook_artifacts.sql")
        .replace("CREATE TABLE", "CREATE TEMP TABLE");
    sqlx::raw_sql(&ddl).execute(&mut *tx).await.unwrap();
    let insert = "INSERT INTO pyloros_hook_artifacts (sha256, component, abi, installed_by)
                  VALUES (COALESCE($1, encode(sha256($2), 'hex')), $2, $3, $4)";
    for (digest, bytes, ok) in [
        (None, vec![1u8], true),
        (Some("invalid"), vec![1], false),
        (None, vec![], false),
        (None, vec![0; MAX_BYTES + 1], false),
    ] {
        sqlx::query("SAVEPOINT fixture")
            .execute(&mut *tx)
            .await
            .unwrap();
        let outcome = sqlx::query(insert)
            .bind(digest)
            .bind(bytes)
            .bind(ABI)
            .bind(Uuid::new_v4())
            .execute(&mut *tx)
            .await;
        assert_eq!(outcome.is_ok(), ok);
        if let Err(e) = outcome {
            assert_eq!(
                e.as_database_error().unwrap().code().as_deref(),
                Some("23514")
            );
        }
        sqlx::query("ROLLBACK TO fixture")
            .execute(&mut *tx)
            .await
            .unwrap();
    }
}
