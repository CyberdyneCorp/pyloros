//! Authenticator settings visible to the account owner.
use super::*;

pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    serve(&state, method, &headers, View::Enrollment).await
}

pub(super) async fn read(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Response, sqlx::Error> {
    let (enabled, remaining) = sqlx::query_as::<_, (bool, i64)>(
        "SELECT totp_enabled, CASE WHEN totp_enabled THEN (
            SELECT count(*) FROM mfa_recovery_codes WHERE user_id = users.id AND used_at IS NULL
         ) ELSE 0 END FROM users WHERE id=$1",
    )
    .bind(user)
    .fetch_one(&mut **tx)
    .await?;
    Ok(Json(json!({"enabled":enabled,"recovery_codes_remaining":remaining})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn remaining_codes_follow_enrollment_and_only_count_the_owner() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE users (id uuid,totp_enabled boolean);
                       CREATE TEMP TABLE mfa_recovery_codes(user_id uuid,used_at timestamptz);",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES ($1,false)")
            .bind(user)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO mfa_recovery_codes VALUES ($1,NULL),($1,now()),($2,NULL)")
            .bind(user)
            .bind(Uuid::new_v4())
            .execute(&mut *tx)
            .await
            .unwrap();
        for (enabled, count) in [(false, 0), (true, 1)] {
            sqlx::query("UPDATE users SET totp_enabled=$1 WHERE id=$2")
                .bind(enabled)
                .bind(user)
                .execute(&mut *tx)
                .await
                .unwrap();
            let body = read(&mut tx, user).await.unwrap().into_body();
            let bytes = to_bytes(body, 256).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&bytes).unwrap(),
                json!({"enabled":enabled,"recovery_codes_remaining":count})
            );
        }
    }
}
