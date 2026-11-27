//! Run the graph migration over existing accounts and OAuth clients.
use sqlx::{Acquire, PgPool};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn graph_edges_follow_account_and_client_lifecycles() -> sqlx::Result<()> {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
    let mut tx = pool.begin().await?;
    let schema = format!("graph_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema};
         CREATE TABLE users (id uuid PRIMARY KEY);
         CREATE TABLE oauth_clients (id uuid PRIMARY KEY);
         INSERT INTO users VALUES (gen_random_uuid());
         INSERT INTO oauth_clients VALUES (gen_random_uuid()), (gen_random_uuid());"
    ))
    .execute(&mut *tx)
    .await?;
    let ddl = include_str!("../migrations/005_relationship_graphs.sql")
        .trim()
        .strip_prefix("BEGIN;")
        .unwrap()
        .strip_suffix("COMMIT;")
        .unwrap();
    sqlx::raw_sql(ddl).execute(&mut *tx).await?;
    sqlx::raw_sql(
        "INSERT INTO pyloros_relationship_models SELECT id, '{}' FROM oauth_clients;
         INSERT INTO pyloros_user_relationships
             SELECT c.id,'document','42','reader',u.id FROM oauth_clients c CROSS JOIN users u;
         INSERT INTO pyloros_object_relationships
             SELECT id,'document','42','parent','folder','archive' FROM oauth_clients;",
    )
    .execute(&mut *tx)
    .await?;

    for table in ["pyloros_user_relationships", "pyloros_object_relationships"] {
        let query = format!("INSERT INTO {table} SELECT * FROM {table} ON CONFLICT DO NOTHING");
        assert_eq!(
            sqlx::query(&query).execute(&mut *tx).await?.rows_affected(),
            0
        );
    }
    let counts = "SELECT (SELECT count(*) FROM pyloros_relationship_models),
                         (SELECT count(*) FROM pyloros_user_relationships),
                         (SELECT count(*) FROM pyloros_object_relationships)";
    let mut erase = tx.begin().await?;
    sqlx::query("DELETE FROM users")
        .execute(&mut *erase)
        .await?;
    let erased: (i64, i64, i64) = sqlx::query_as(counts).fetch_one(&mut *erase).await?;
    assert_eq!(erased, (2, 0, 2));
    erase.rollback().await?;

    let removed: Uuid = sqlx::query_scalar(
        "DELETE FROM oauth_clients WHERE id=(SELECT id FROM oauth_clients LIMIT 1) RETURNING id",
    )
    .fetch_one(&mut *tx)
    .await?;
    let remaining: (i64, i64, i64) = sqlx::query_as(counts).fetch_one(&mut *tx).await?;
    assert_eq!(remaining, (1, 1, 1));
    let owners: Vec<Uuid> = sqlx::query_scalar(
        "SELECT client_id FROM pyloros_user_relationships UNION SELECT client_id FROM pyloros_object_relationships",
    )
    .fetch_all(&mut *tx)
    .await?;
    assert_eq!(owners.len(), 1);
    assert_ne!(owners[0], removed);
    tx.rollback().await
}
