use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;

#[derive(Serialize)]
pub struct Report {
    pub active_unbound: usize,
    hooks: Vec<Value>,
}

pub async fn read(pool: &PgPool) -> sqlx::Result<Report> {
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
    let query = format!(
        "SELECT h.is_active AND b.sha256 IS NULL, jsonb_build_object(
            'id', h.id, 'name', h.name, 'event', h.event_type, 'active', h.is_active,
            'source_sha256', encode(sha256(convert_to(h.code, 'UTF8')), 'hex'),
            'component_sha256', b.sha256)
         FROM hooks h LEFT JOIN ({selections}) b ON h.id = b.hook_id ORDER BY h.id"
    );
    let rows: Vec<(bool, Value)> = sqlx::query_as(&query).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Report {
        active_unbound: rows.iter().filter(|(unbound, _)| *unbound).count(),
        hooks: rows.into_iter().map(|(_, hook)| hook).collect(),
    })
}
