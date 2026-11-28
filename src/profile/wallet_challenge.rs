//! Public status of a wallet sign-in challenge.
pub(super) mod issue;
use super::*;
use crate::login_http::problem;
use axum::extract::Path;

pub(super) async fn get(
    State(state): State<Arc<Profile>>,
    method: Method,
    Path(raw): Path<String>,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let id = match crate::query::path_uuid(&raw, "challenge_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let Ok(tx) = state.pool.begin().await else {
        return missing();
    };
    status_response(tx, id).await
}

async fn status_response(mut tx: Transaction<'_, Postgres>, id: Uuid) -> Response {
    match read(&mut tx, id).await {
        Ok(Some(response)) => {
            // Expiry describes the challenge at read time, even if a deferred write fails.
            if tx.commit().await.is_err() {
                eprintln!("could not commit wallet challenge status read");
            }
            response
        }
        _ => missing(),
    }
}

fn missing() -> Response {
    problem(StatusCode::NOT_FOUND, "Challenge not found")
}

async fn read(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<Response>, sqlx::Error> {
    let row = sqlx::query_as::<_, (Option<String>, String, Option<DateTime<Utc>>, String)>(
        "SELECT wallet_address,status,expires_at,COALESCE(extra_metadata::text,'null')
         FROM auth_challenges WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((address, status, expires_at, metadata)) = row else {
        return Ok(None);
    };
    admin_organizations::normalized_storage(&metadata)?;
    let status = match status.as_str() {
        "pending" if expires_at.is_some_and(|expiry| expiry < Utc::now()) => {
            sqlx::query("UPDATE auth_challenges SET status='expired' WHERE id=$1")
                .bind(id)
                .execute(&mut **tx)
                .await?;
            "expired"
        }
        value @ ("pending" | "consumed" | "expired" | "failed" | "completed") => value,
        _ => return Ok(None),
    };
    let remaining = expires_at.map_or(0, |expiry| (expiry - Utc::now()).num_seconds().max(0));
    Ok(Some(Json(json!({
        "challenge_id": id, "wallet_address": address, "status": status, "expires_in_seconds": remaining,
    })).into_response()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn expired_read_updates_only_pending_challenges() -> Result<(), sqlx::Error> {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(
            "CREATE TEMP TABLE auth_challenges(id uuid PRIMARY KEY, wallet_address text,
            status text, expires_at timestamptz, extra_metadata jsonb) ON COMMIT DROP",
        )
        .execute(&mut *tx)
        .await?;
        for (stored, expected) in [
            ("pending", "expired"),
            ("completed", "completed"),
            ("failed", "failed"),
        ] {
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO auth_challenges VALUES($1, 'wallet', $2, now()-interval '1 day', '{}')")
                .bind(id).bind(stored).execute(&mut *tx).await?;
            let response = read(&mut tx, id).await?.unwrap();
            let bytes = axum::body::to_bytes(response.into_body(), 512)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                body,
                json!({"challenge_id":id, "status":expected, "wallet_address":"wallet", "expires_in_seconds":0})
            );
            let persisted: String =
                sqlx::query_scalar("SELECT status FROM auth_challenges WHERE id=$1")
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await?;
            assert_eq!(persisted, expected);
        }
        tx.rollback().await
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn deferred_expiry_failure_returns_observed_status() -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql(
            "CREATE TEMP TABLE known_status(value text PRIMARY KEY);
            INSERT INTO known_status VALUES('pending');
            CREATE TEMP TABLE auth_challenges(id uuid PRIMARY KEY,wallet_address text,
              status text REFERENCES known_status(value) DEFERRABLE INITIALLY DEFERRED,
              expires_at timestamptz,extra_metadata jsonb);",
        )
        .execute(&pool)
        .await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO auth_challenges VALUES($1,'wallet','pending',now()-interval '1 hour','{}')")
            .bind(id).execute(&pool).await?;
        let response = status_response(pool.begin().await?, id).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "expired");
        let status: String = sqlx::query_scalar("SELECT status FROM auth_challenges WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await?;
        assert_eq!(status, "pending");
        Ok(())
    }
}
