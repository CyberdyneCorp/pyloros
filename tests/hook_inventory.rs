use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::process::{Command, Output};
use url::Url;
use uuid::Uuid;

fn inventory(url: &Url, events: &[&str]) -> Output {
    check(url, "--check-hook-bindings", events)
}

fn check(url: &Url, command: &str, events: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pyloros"))
        .arg(command)
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
    assert_retirement_coverage(&url, &[], 2, 1);
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
    assert_retirement_coverage(&url, &[], 1, 0);
    assert_retirement_coverage(&url, &["role_granted"], 0, 0);
    assert_retirement_coverage(&url, &["user_registered"], 1, 0);
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
    sqlx::raw_sql("INSERT INTO pyloros_hook_bindings SELECT id,repeat('c',64) FROM hooks")
        .execute(&mut *conn)
        .await?;
    assert_retirement_coverage(&url, &[], 0, 0);
    check_queue_visibility(&url, &mut conn).await?;
    check_delivery_visibility(&url, &mut conn).await?;
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

fn assert_retirement_coverage(url: &Url, events: &[&str], total: u64, active: u64) {
    let args = [&["--include-inactive"][..], events].concat();
    let output = inventory(url, &args);
    assert_eq!(output.status.code(), Some(if total == 0 { 0 } else { 2 }));
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(data["all_unbound"], total);
    assert_eq!(data["active_unbound"], active);
}

async fn check_queue_visibility(url: &Url, conn: &mut sqlx::PgConnection) -> sqlx::Result<()> {
    let queue = |events: &[&str], code: i32, count: Option<i64>| {
        let output = check(url, "--check-hook-queue", events);
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        match count {
            Some(n) => assert_eq!(
                serde_json::from_slice::<Value>(&output.stdout).unwrap(),
                json!({"pending":n})
            ),
            None => assert!(output.stdout.is_empty()),
        }
    };
    queue(&[], 1, None);
    sqlx::raw_sql("CREATE TABLE pyloros_hook_deliveries(event_type text, available_at timestamptz);
        INSERT INTO pyloros_hook_deliveries VALUES ('entitlement_granted', now() + interval '1 hour'), ('entitlement_revoked', now()), ('role_granted', now())")
        .execute(&mut *conn).await?;
    let billing = [
        "entitlement_granted",
        "entitlement_revoked",
        "entitlement_granted",
    ];
    queue(&[], 2, Some(3));
    queue(&billing, 2, Some(2));
    queue(&["user_registered"], 0, Some(0));
    queue(&["entitlement_granted", "unknown"], 1, None);
    check_hook_queue_filter(url, conn).await?;
    use sqlx::Connection;
    let mut tx = conn.begin().await?;
    sqlx::query("DELETE FROM pyloros_hook_deliveries WHERE event_type = ANY($1)")
        .bind(&billing[..])
        .execute(&mut *tx)
        .await?;
    queue(&billing, 2, Some(2));
    tx.commit().await?;
    queue(&billing, 0, Some(0));
    queue(&[], 2, Some(1));
    Ok(())
}

async fn check_hook_queue_filter(url: &Url, conn: &mut sqlx::PgConnection) -> sqlx::Result<()> {
    use sqlx::Connection;
    let first = Uuid::from_u128(1).to_string();
    let sibling = Uuid::from_u128(2).to_string();
    let count = |id: &str, expected: i64| {
        let output = check(url, "--check-hook-queue", &["--hook", id]);
        assert_eq!(
            output.status.code(),
            Some(if expected == 0 { 0 } else { 2 })
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!({"pending":expected})
        );
    };
    for args in [
        vec!["--hook"],
        vec!["--hook", "invalid"],
        vec!["--hook", &first, "role_granted"],
        vec!["role_granted", "--hook", &first],
    ] {
        let output = check(url, "--check-hook-queue", &args);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    sqlx::raw_sql("ALTER TABLE pyloros_hook_deliveries ADD COLUMN hook_id uuid REFERENCES hooks(id) ON DELETE CASCADE;
        UPDATE pyloros_hook_deliveries SET hook_id = (SELECT id FROM hooks WHERE is_active);
        INSERT INTO pyloros_hook_deliveries SELECT 'entitlement_granted',now(),id FROM hooks WHERE NOT is_active")
        .execute(&mut *conn).await?;
    count(&first, 3);
    count(&sibling, 1);
    let mut tx = conn.begin().await?;
    sqlx::query("DELETE FROM hooks WHERE NOT is_active")
        .execute(&mut *tx)
        .await?;
    count(&sibling, 1);
    tx.rollback().await?;
    count(&sibling, 1);
    sqlx::query("DELETE FROM hooks WHERE NOT is_active")
        .execute(&mut *conn)
        .await?;
    count(&sibling, 0);
    count(&first, 3);
    Ok(())
}

async fn check_delivery_visibility(url: &Url, conn: &mut sqlx::PgConnection) -> sqlx::Result<()> {
    use sqlx::Connection;
    let id = Uuid::new_v4();
    let arg = id.to_string();
    let inspect = || check(url, "--inspect-hook-delivery", &[&arg]);
    let report = || {
        let output = inspect();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    for args in [&[][..], &["invalid"], &[&arg, &arg]] {
        let output = check(url, "--inspect-hook-delivery", args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    let missing_table = inspect();
    assert!(!missing_table.status.success());
    assert!(missing_table.stdout.is_empty());
    sqlx::raw_sql(
        "ALTER TABLE pyloros_hook_deliveries ADD COLUMN id uuid;
        CREATE TABLE hook_executions(id uuid PRIMARY KEY,status text NOT NULL)",
    )
    .execute(&mut *conn)
    .await?;
    assert_eq!(report(), json!({"pending":false,"execution_status":null}));
    sqlx::query("INSERT INTO pyloros_hook_deliveries(id) VALUES($1)")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    for commit in [false, true] {
        let mut tx = conn.begin().await?;
        sqlx::query("INSERT INTO hook_executions VALUES($1,'timeout')")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM pyloros_hook_deliveries WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        assert_eq!(report(), json!({"pending":true,"execution_status":null}));
        if commit {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
    }
    assert_eq!(
        report(),
        json!({"pending":false,"execution_status":"timeout"})
    );
    Ok(())
}
