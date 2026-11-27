//! Verify the shared hook migration against updates from an independent SQL writer.
use sqlx::{Acquire, PgPool};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn source_edits_invalidate_only_committed_selections() -> sqlx::Result<()> {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
    let mut tx = pool.begin().await?;
    let schema = format!("hook_edit_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema}"
    ))
    .execute(&mut *tx)
    .await?;
    sqlx::raw_sql(
        "CREATE TABLE hooks(id uuid PRIMARY KEY,code text,name text);
        CREATE TABLE pyloros_hook_artifacts(sha256 text PRIMARY KEY);
        CREATE TABLE users(id uuid PRIMARY KEY);",
    )
    .execute(&mut *tx)
    .await?;
    for ddl in [
        include_str!("../migrations/002_hook_bindings.sql"),
        include_str!("../migrations/003_hook_deliveries.sql"),
    ] {
        sqlx::raw_sql(ddl).execute(&mut *tx).await?;
    }
    let edited = Uuid::new_v4();
    let other = Uuid::new_v4();
    sqlx::query("INSERT INTO hooks VALUES ($1,'original','first'),($2,'original','second')")
        .bind(edited)
        .bind(other)
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql("INSERT INTO pyloros_hook_artifacts VALUES ('selected');
        INSERT INTO pyloros_hook_bindings SELECT id,'selected' FROM hooks;
        INSERT INTO pyloros_hook_deliveries(id,hook_id,sha256,hook_name,event_type,payload,timeout_seconds)
        SELECT gen_random_uuid(),id,'selected',name,'user_registered','{}',1 FROM hooks;")
        .execute(&mut *tx).await?;
    // The outer test transaction owns setup and cleanup.
    let migration = include_str!("../migrations/004_invalidate_edited_hook_bindings.sql")
        .trim()
        .strip_prefix("BEGIN;")
        .unwrap()
        .strip_suffix("COMMIT;")
        .unwrap();
    sqlx::raw_sql(migration).execute(&mut *tx).await?;
    sqlx::query("UPDATE hooks SET code=code,name='renamed' WHERE id=$1")
        .bind(edited)
        .execute(&mut *tx)
        .await?;
    let mut edit = tx.begin().await?;
    sqlx::query("UPDATE hooks SET code='new' WHERE id=$1")
        .bind(edited)
        .execute(&mut *edit)
        .await?;
    edit.rollback().await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM pyloros_hook_bindings")
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(count, 2);
    sqlx::query("UPDATE hooks SET code='new' WHERE id=$1")
        .bind(edited)
        .execute(&mut *tx)
        .await?;
    let remaining: Vec<Uuid> = sqlx::query_scalar("SELECT hook_id FROM pyloros_hook_bindings")
        .fetch_all(&mut *tx)
        .await?;
    assert_eq!(remaining, [other]);
    let pinned: String =
        sqlx::query_scalar("SELECT sha256 FROM pyloros_hook_deliveries WHERE hook_id=$1")
            .bind(edited)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(pinned, "selected");
    tx.rollback().await
}
