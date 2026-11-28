//! Create an IAM role and record its operator audit atomically.
use super::*;
use crate::{grant_response::SessionOrigin, request_json::iam_document};

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let raw = match iam_document::document(&headers, &bytes) {
        Ok(raw) => raw,
        Err(error) => return *error,
    };
    let (mut tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let Some(raw) = raw else {
        return internal();
    };
    let role = match input::role(&raw) {
        Ok(role) => role,
        Err(error) => return *error,
    };
    let name = role["name"].as_str().expect("validated role name");
    let description = role["description"].as_str();
    let seconds = role["max_session_duration_s"]
        .as_str()
        .expect("validated duration");
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    let actor = (actor, email.as_deref());
    if let Some(chain) = chain {
        if chain.lock_signer(&mut tx).await.is_err() {
            return internal();
        }
        let Ok(role) = chain.create_role(name, description, seconds).await else {
            return internal();
        };
        return finish(tx, role.id, actor, origin, role)
            .await
            .unwrap_or_else(|_| internal());
    }
    let Ok(duration) = seconds.parse::<i32>() else {
        return internal();
    };
    insert(tx, name, description, duration, actor, origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn insert(
    mut tx: Transaction<'_, Postgres>,
    name: &str,
    description: Option<&str>,
    duration: i32,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO iam_roles (id,name,description,max_session_duration_s) VALUES ($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .bind(duration)
    .execute(&mut *tx)
    .await?;
    let role = json!({"id":id,"name":name,"description":description,"is_active":true,"chain_role_id":null,
            "max_session_duration_s":duration,"created_at":null});
    finish(tx, id, actor, origin, role).await
}

async fn finish(
    mut tx: Transaction<'_, Postgres>,
    id: Uuid,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
    role: impl serde::Serialize,
) -> Result<Response, sqlx::Error> {
    crate::admin_audit::append(
        &mut tx,
        "iam.role.create",
        Some(actor),
        ("iam_role", &id.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(role)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn an_audit_failure_rolls_back_the_new_role() -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE iam_roles(id uuid,name text,description text,max_session_duration_s integer);
            CREATE TEMP TABLE audit_chain_head(id int primary key,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text CHECK(false),target_type text,target_id text,extra_metadata jsonb,ip_address inet,user_agent text,created_at timestamptz,prev_hash text,row_hash text,actor_user_id uuid,actor_type text,actor_client_id text,actor_email text);"
        ).execute(&pool).await?;
        let failed = insert(
            pool.begin().await?,
            "operators",
            None,
            3600,
            (Uuid::new_v4(), None),
            SessionOrigin {
                ip: None,
                user_agent: None,
            },
        )
        .await;
        assert_eq!(
            failed
                .unwrap_err()
                .as_database_error()
                .and_then(|e| e.code())
                .as_deref(),
            Some("23514")
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM iam_roles")
            .fetch_one(&pool)
            .await?;
        assert_eq!(count, 0);
        Ok(())
    }
}
