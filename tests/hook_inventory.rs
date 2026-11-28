use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::process::{Command, Output};
use url::Url;
use uuid::Uuid;

fn inventory(url: &Url, events: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pyloros"))
        .arg("--check-hook-bindings")
        .args(events)
        .env("DATABASE_URL", url.as_str())
        .env("BIND_ADDR", "invalid") // Inventory must run without starting HTTP.
        .output()
        .unwrap()
}

fn report(url: &Url, code: i32) -> Value {
    let output = inventory(url, &[]);
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn inventory_tracks_active_hooks_across_binding_migration() -> sqlx::Result<()> {
    let dsn = std::env::var("DATABASE_URL").unwrap();
    let pool = PgPool::connect(&dsn).await?;
    let mut conn = pool.acquire().await?;
    let schema = format!("inventory_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .execute(&mut *conn)
    .await?;
    let mut url = Url::parse(&dsn).unwrap();
    url.query_pairs_mut().append_pair(
        "options",
        &format!("-c search_path={schema} -c default_transaction_read_only=on"),
    );

    let missing = inventory(&url, &[]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(missing.stdout.is_empty());
    sqlx::raw_sql("CREATE TABLE hooks (id uuid PRIMARY KEY, name text, event_type text, is_active boolean, code text)")
        .execute(&mut *conn).await?;
    assert_eq!(report(&url, 0), json!({"active_unbound":0,"hooks":[]}));
    let active = Uuid::from_u128(1);
    let inactive = Uuid::from_u128(2);
    let source = "fixture π";
    sqlx::query("INSERT INTO hooks VALUES ($2,'archived','user_registered',false,'old'), ($1,'enabled','role_granted',true,$3)")
        .bind(active).bind(inactive).bind(source).execute(&mut *conn).await?;
    let before = report(&url, 2);
    assert_eq!(before["active_unbound"], 1);
    assert_eq!(
        before["hooks"][0],
        json!({
            "id":active, "name":"enabled", "event":"role_granted", "active":true,
            "source_sha256":format!("{:x}",Sha256::digest(source.as_bytes())), "component_sha256":null,
            "timeout_seconds":null,"allow_network":null,"receive_pii":null
        })
    );
    assert_eq!(before["hooks"][1]["id"], inactive.to_string());

    sqlx::raw_sql("CREATE TABLE pyloros_hook_artifacts (sha256 text PRIMARY KEY)")
        .execute(&mut *conn)
        .await?;
    sqlx::raw_sql(include_str!("../migrations/002_hook_bindings.sql"))
        .execute(&mut *conn)
        .await?;
    assert_eq!(report(&url, 2), before);
    sqlx::raw_sql(
        "INSERT INTO pyloros_hook_artifacts VALUES (repeat('c',64));
        INSERT INTO pyloros_hook_bindings SELECT id,repeat('c',64) FROM hooks WHERE is_active",
    )
    .execute(&mut *conn)
    .await?;
    let bound = report(&url, 0);
    assert_eq!(bound["active_unbound"], 0);
    assert_eq!(bound["hooks"][0]["component_sha256"], "c".repeat(64));
    assert_eq!(bound["hooks"][1], before["hooks"][1]);
    sqlx::raw_sql("ALTER TABLE hooks ADD COLUMN timeout_seconds integer DEFAULT 7, ADD COLUMN allow_network boolean DEFAULT false")
        .execute(&mut *conn).await?;
    let partial = report(&url, 0);
    assert_eq!(partial["hooks"][0]["timeout_seconds"], 7);
    assert_eq!(partial["hooks"][0]["allow_network"], false);
    assert_eq!(partial["hooks"][0].get("receive_pii"), Some(&Value::Null));

    sqlx::raw_sql("ALTER TABLE hooks ADD COLUMN receive_pii boolean DEFAULT false;
        UPDATE hooks SET allow_network=true, receive_pii=true, timeout_seconds=13 WHERE NOT is_active")
        .execute(&mut *conn).await?;
    let current = report(&url, 0);
    assert_eq!(current["hooks"][0]["receive_pii"], false);
    assert_eq!(current["hooks"][1]["receive_pii"], true);
    assert_eq!(current["hooks"][1]["allow_network"], true);
    assert_eq!(current["hooks"][1]["timeout_seconds"], 13);
    sqlx::raw_sql(include_str!(
        "../migrations/004_invalidate_edited_hook_bindings.sql"
    ))
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE hooks SET code='review again' WHERE id=$1")
        .bind(active)
        .execute(&mut *conn)
        .await?;
    let edited = report(&url, 2);
    assert_eq!(edited["active_unbound"], 1);
    assert!(edited["hooks"][0]["component_sha256"].is_null());
    assert_ne!(
        edited["hooks"][0]["source_sha256"],
        before["hooks"][0]["source_sha256"]
    );
    for (event, expected_code, expected_rows) in [
        ("role_granted", 2, vec![edited["hooks"][0].clone()]),
        ("user_registered", 0, vec![edited["hooks"][1].clone()]),
        ("user_deleted", 0, vec![]),
    ] {
        let output = inventory(&url, &[event]);
        assert_eq!(output.status.code(), Some(expected_code));
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            value,
            json!({"hooks":expected_rows,"active_unbound":usize::from(expected_code==2)})
        );
    }
    let combined = inventory(
        &url,
        &["user_registered", "role_granted", "user_registered"],
    );
    assert_eq!(combined.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&combined.stdout).unwrap(),
        edited
    );
    let unrelated = inventory(&url, &["entitlement_granted", "entitlement_revoked"]);
    assert_eq!(unrelated.status.code(), Some(0));
    assert_eq!(
        serde_json::from_slice::<Value>(&unrelated.stdout).unwrap(),
        json!({"hooks":[],"active_unbound":0})
    );
    for invalid in [&["user_register"][..], &["role_granted", "extra"], &[""]] {
        let output = inventory(&url, invalid);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("hook event"));
    }
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut *conn)
        .await?;
    Ok(())
}
