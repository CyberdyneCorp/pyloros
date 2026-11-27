use super::*;
use crate::grant_response::SessionOrigin;

pub(super) async fn remove(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let id = match crate::query::path_uuid(&raw, "hook_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    match delete(tx, id, actor, email.as_deref(), origin).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => missing(),
        Err(_) => internal(),
    }
}

async fn delete(
    mut tx: Transaction<'_, Postgres>,
    id: Uuid,
    actor: Uuid,
    email: Option<&str>,
    origin: SessionOrigin<'_>,
) -> sqlx::Result<bool> {
    let sql = format!("DELETE FROM hooks WHERE id=$1 RETURNING {FIELDS}");
    let Some(row) = sqlx::query(&sql).bind(id).fetch_optional(&mut *tx).await? else {
        return Ok(false);
    };
    hook(&row)?;
    crate::admin_audit::append(
        &mut tx,
        "hook.delete",
        Some((actor, email)),
        ("hook", &id.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn audit_rejection_restores_the_hook_and_its_history() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE hooks(id uuid PRIMARY KEY,name text,event_type text,code text,is_active boolean,
            timeout_seconds integer,allow_network boolean,receive_pii boolean,created_at timestamptz,updated_at timestamptz);
            CREATE TEMP TABLE hook_executions(hook_id uuid REFERENCES hooks(id) ON DELETE CASCADE);
            CREATE TEMP TABLE audit_chain_head(id int PRIMARY KEY,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text,target_type text,target_id text,extra_metadata jsonb,
                ip_address inet,user_agent text,created_at timestamptz,prev_hash text,row_hash text,actor_user_id uuid,
                actor_type text,actor_client_id text,actor_email text,CONSTRAINT reject_delete CHECK(action <> 'hook.delete'));")
            .execute(&pool).await.unwrap();
        let id = Uuid::new_v4();
        let actor = Uuid::new_v4();
        sqlx::query("INSERT INTO hooks VALUES($1,'test','user_registered','sample',false,5,false,false,now(),now())")
            .bind(id).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO hook_executions VALUES($1)")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let remove = || async {
            delete(
                pool.begin().await?,
                id,
                actor,
                None,
                SessionOrigin {
                    ip: None,
                    user_agent: None,
                },
            )
            .await
        };
        let counts = || {
            sqlx::query_as::<_,(i64,i64,i64)>("SELECT (SELECT count(*) FROM hooks),(SELECT count(*) FROM hook_executions),(SELECT count(*) FROM admin_action_logs)").fetch_one(&pool)
        };
        assert!(remove().await.is_err());
        assert_eq!(counts().await.unwrap(), (1, 1, 0));
        sqlx::query("ALTER TABLE admin_action_logs DROP CONSTRAINT reject_delete")
            .execute(&pool)
            .await
            .unwrap();
        assert!(remove().await.unwrap());
        assert!(!remove().await.unwrap());
        assert_eq!(counts().await.unwrap(), (0, 0, 1));
    }
}
