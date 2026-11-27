//! Remove an unattached policy and commit its operator audit in the same transaction.
use super::*;
use crate::grant_response::SessionOrigin;

pub(in crate::profile) async fn remove(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Response {
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let id = match crate::query::path_uuid(&path, "policy_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    if let Some(chain) = chain {
        if tx.commit().await.is_err() {
            return internal();
        }
        return writes::prepare_chain_write(
            &chain,
            crate::chain_settings::IamMutation::DeletePolicy(id),
        )
        .await;
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    delete(tx, id, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn delete(
    mut tx: Transaction<'_, Postgres>,
    id: Uuid,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    // Concurrent FK inserts acquire KEY SHARE on the parent. Lock before
    // inspecting attachments so a committed attachment cannot be cascaded away.
    let locked =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM iam_policies WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if locked.is_none() {
        return Ok(writes::missing(id));
    }
    statements::policies(&mut tx, Some(id)).await?;
    let attached = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT FROM iam_identity_policies WHERE policy_id=$1)
             OR EXISTS(SELECT FROM iam_group_policies WHERE policy_id=$1)
             OR EXISTS(SELECT FROM iam_role_policies WHERE policy_id=$1)
             OR EXISTS(SELECT FROM iam_permission_boundaries WHERE policy_id=$1)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if attached {
        return Ok(crate::login_http::problem(
            StatusCode::CONFLICT,
            &format!("policy {id} is still attached"),
        ));
    }
    sqlx::query("DELETE FROM iam_policies WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    commit_deletion(tx, actor, "iam.policy.delete", ("iam_policy", id), origin).await
}

pub(super) async fn commit_deletion(
    mut tx: Transaction<'_, Postgres>,
    actor: (Uuid, Option<&str>),
    action: &str,
    target: (&str, Uuid),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    crate::admin_audit::append(
        &mut tx,
        action,
        Some(actor),
        (target.0, &target.1.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::NO_CONTENT,
        [(header::CONTENT_TYPE, "application/json")],
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn boundary_prevents_deletion_and_success_returns_an_empty_json_response()
    -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE iam_policies(id uuid primary key,name text,description text,version int,is_active bool,chain_policy_id int,created_at timestamptz default now());
            CREATE TEMP TABLE iam_policy_statements(policy_id uuid, sid text,effect text,actions jsonb,resources jsonb,conditions jsonb,sort_order int);
            CREATE TEMP TABLE iam_identity_policies(policy_id uuid);
            CREATE TEMP TABLE iam_role_policies(policy_id uuid);
            CREATE TEMP TABLE iam_group_policies(policy_id uuid);
            CREATE TEMP TABLE iam_permission_boundaries(policy_id uuid);
            CREATE TEMP TABLE audit_chain_head(id int primary key,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text,target_type text,target_id text,extra_metadata jsonb,ip_address inet,user_agent text,created_at timestamptz,prev_hash text,row_hash text,actor_user_id uuid,actor_email text);")
            .execute(&pool).await?;
        let id = Uuid::new_v4();
        let actor = (Uuid::new_v4(), None);
        let origin = || SessionOrigin {
            ip: None,
            user_agent: None,
        };
        sqlx::query("INSERT INTO iam_policies(id) VALUES($1)")
            .bind(id)
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO iam_permission_boundaries VALUES($1)")
            .bind(id)
            .execute(&pool)
            .await?;
        let refused = delete(pool.begin().await?, id, actor, origin()).await?;
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        sqlx::query("DELETE FROM iam_permission_boundaries")
            .execute(&pool)
            .await?;
        let deleted = delete(pool.begin().await?, id, actor, origin()).await?;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        assert_eq!(deleted.headers()[header::CONTENT_TYPE], "application/json");
        assert!(
            axum::body::to_bytes(deleted.into_body(), 1)
                .await
                .unwrap()
                .is_empty()
        );
        let events: Vec<String> = sqlx::query_scalar("SELECT action FROM admin_action_logs")
            .fetch_all(&pool)
            .await?;
        assert_eq!(events, ["iam.policy.delete"]);
        Ok(())
    }
}
