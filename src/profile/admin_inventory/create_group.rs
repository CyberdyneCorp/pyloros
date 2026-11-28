//! Create an ordinary IAM group and record its operator audit atomically.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem, request_json::iam_document};

pub(in crate::profile) async fn create_group(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let raw = match iam_document::document(&headers, &bytes) {
        Ok(raw) => raw,
        Err(error) => return *error,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let Some(raw) = raw else {
        return internal();
    };
    let group = match input::group(&raw) {
        Ok(group) => group,
        Err(error) => return *error,
    };
    let name = group["name"].as_str().expect("validated group name");
    if name.starts_with("rp:") {
        return problem(
            StatusCode::BAD_REQUEST,
            "group names starting with 'rp:' are reserved for client roles — use the client-role endpoints",
        );
    }
    let description = group["description"].as_str();
    if let Some(chain) = chain {
        return prepare_chain_group(tx, &chain, name, description)
            .await
            .unwrap_or_else(|_| internal());
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    insert(tx, name, description, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn prepare_chain_group(
    tx: Transaction<'_, Postgres>,
    chain: &crate::chain_settings::Chain,
    name: &str,
    description: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let result = chain
        .with_signer_lock(tx, chain.prepare_group_creation(name, description))
        .await?;
    Ok(match result {
        Ok(_) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Blockchain transaction submission unavailable",
        ),
        Err(_) => internal(),
    })
}

async fn insert(
    mut tx: Transaction<'_, Postgres>,
    name: &str,
    description: Option<&str>,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO iam_groups (id,name,description) VALUES ($1,$2,$3)")
        .bind(id)
        .bind(name)
        .bind(description)
        .execute(&mut *tx)
        .await?;
    crate::admin_audit::append(
        &mut tx,
        "iam.group.create",
        Some(actor),
        ("iam_group", &id.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    // Creation returns the new group before the inventory loads its database timestamp.
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id":id,"name":name,"description":description,"is_active":true,"chain_group_id":null,
            "policy_ids":[],"member_count":0,"created_at":null
        })),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn an_audit_failure_rolls_back_the_new_group() -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE iam_groups(id uuid,name text,description text);
            CREATE TEMP TABLE audit_chain_head(id int primary key,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text CHECK(false),target_type text,target_id text,extra_metadata jsonb,ip_address inet,user_agent text,created_at timestamptz,prev_hash text,row_hash text,actor_user_id uuid,actor_type text,actor_client_id text,actor_email text);"
        ).execute(&pool).await?;
        let failed = insert(
            pool.begin().await?,
            "operators",
            None,
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
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM iam_groups")
            .fetch_one(&pool)
            .await?;
        assert_eq!(count, 0);
        Ok(())
    }

    use std::time::Duration;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn group_preparation_waits_for_the_signer_and_releases_it_on_error() {
        let db = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let chain = crate::chain_settings::Chain::for_health_test("http://localhost".into());
        let mut owner = db.begin().await.unwrap();
        chain.lock_signer(&mut owner).await.unwrap();
        let tx = db.begin().await.unwrap();
        let preparing = prepare_chain_group(tx, &chain, "reports", None);
        tokio::pin!(preparing);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut preparing)
                .await
                .is_err()
        );
        owner.rollback().await.unwrap();
        // The fixture has no group contract, so preparation ends before any network call.
        let response = tokio::time::timeout(Duration::from_secs(2), preparing)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let mut next = db.begin().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), chain.lock_signer(&mut next))
            .await
            .unwrap()
            .unwrap();
    }
}
