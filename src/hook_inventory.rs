use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;

#[derive(Serialize)]
pub struct Report {
    pub active_unbound: usize,
    hooks: Vec<Value>,
}

pub async fn read(pool: &PgPool, events: &[&str]) -> sqlx::Result<Report> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let migrated: bool =
        sqlx::query_scalar("SELECT to_regclass('pyloros_hook_bindings') IS NOT NULL")
            .fetch_one(&mut *tx)
            .await?;
    let selections = if migrated {
        "SELECT hook_id, sha256 FROM pyloros_hook_bindings"
    } else {
        "SELECT NULL::uuid AS hook_id, NULL::text AS sha256 WHERE false"
    };
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT attname::text FROM pg_attribute
         WHERE attrelid='hooks'::regclass AND attnum > 0 AND NOT attisdropped",
    )
    .fetch_all(&mut *tx)
    .await?;
    let settings = ["timeout_seconds", "allow_network", "receive_pii"].map(|name| {
        if columns.iter().any(|column| column == name) {
            format!("'{name}', h.{name}")
        } else {
            format!("'{name}', NULL")
        }
    });
    let settings = settings.join(", ");
    let query = format!(
        "SELECT h.is_active AND b.sha256 IS NULL, jsonb_build_object(
            'id', h.id, 'name', h.name, 'event', h.event_type, 'active', h.is_active,
            'source_sha256', encode(sha256(convert_to(h.code, 'UTF8')), 'hex'),
            'component_sha256', b.sha256, {settings})
         FROM hooks h LEFT JOIN ({selections}) b ON h.id = b.hook_id
         WHERE cardinality($1::text[]) = 0 OR h.event_type = ANY($1) ORDER BY h.id"
    );
    let rows: Vec<(bool, Value)> = sqlx::query_as(&query)
        .bind(events)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Report {
        active_unbound: rows.iter().filter(|(unbound, _)| *unbound).count(),
        hooks: rows.into_iter().map(|(_, hook)| hook).collect(),
    })
}

pub async fn pending(pool: &PgPool, events: &[&str]) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT count(*) FROM pyloros_hook_deliveries WHERE cardinality($1::text[]) = 0 OR event_type = ANY($1)")
        .bind(events)
        .fetch_one(pool)
        .await
}

pub async fn pending_for_hook(pool: &PgPool, id: uuid::Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT count(hook_id) FROM pyloros_hook_deliveries WHERE hook_id=$1")
        .bind(id)
        .fetch_one(pool)
        .await
}

pub async fn delivery(pool: &PgPool, id: uuid::Uuid) -> sqlx::Result<Value> {
    sqlx::query_scalar(
        "SELECT jsonb_build_object(
            'pending', EXISTS(SELECT id FROM pyloros_hook_deliveries WHERE id=$1),
            'execution_status', (SELECT status FROM hook_executions WHERE id=$1))",
    )
    .bind(id)
    .fetch_one(pool)
    .await
}
