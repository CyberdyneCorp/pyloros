//! Remove a group, its inherited grants and its memberships in one audited transaction.
use super::*;
use crate::{chain_settings::IamMutation, grant_response::SessionOrigin, login_http::problem};

pub(in crate::profile) async fn delete_group(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    axum::extract::Path(raw): axum::extract::Path<String>,
) -> Response {
    if method != Method::DELETE {
        let mut result = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        result
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
        return result;
    }
    let (mut tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let id = match crate::query::path_uuid(&raw, "group_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    let actor = (actor, email.as_deref());
    if let Some(chain) = chain {
        let mutation = IamMutation::DeleteGroup(id);
        if chain.lock_signer(&mut tx).await.is_err() {
            return internal();
        }
        if let Err(error) = chain.submit_mutation(&mutation).await {
            return writes::preparation_error(&mutation, error);
        }
        return removal::commit_deletion(tx, actor, "iam.group.delete", ("iam_group", id), origin)
            .await
            .unwrap_or_else(|_| internal());
    }
    delete(tx, id, actor, origin)
        .await
        .unwrap_or_else(|_| internal())
}

pub(super) fn protected() -> Response {
    problem(
        StatusCode::BAD_REQUEST,
        "group names starting with 'rp:' are client roles — use the client-role endpoints (/admin/clients/{client_id}/roles, /admin/users/{user_id}/roles)",
    )
}
pub(super) fn missing(id: Uuid) -> Response {
    problem(StatusCode::NOT_FOUND, &format!("group {id}"))
}

async fn delete(
    mut tx: Transaction<'_, Postgres>,
    id: Uuid,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let name =
        sqlx::query_scalar::<_, String>("SELECT name FROM iam_groups WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(name) = name else {
        return Ok(missing(id));
    };
    if name.starts_with("rp:") {
        return Ok(protected());
    }
    // Foreign keys cascade only the association rows. The identities and policies survive.
    sqlx::query("DELETE FROM iam_groups WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    removal::commit_deletion(tx, actor, "iam.group.delete", ("iam_group", id), origin).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn deleting_a_role_group_preserves_the_group_without_an_audit() -> Result<(), sqlx::Error>
    {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql(
            "CREATE TEMP TABLE iam_groups(id uuid primary key,name text);
                       CREATE TEMP TABLE admin_action_logs(action text);",
        )
        .execute(&pool)
        .await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO iam_groups VALUES($1,'rp:client:owner')")
            .bind(id)
            .execute(&pool)
            .await?;
        let response = delete(
            pool.begin().await?,
            id,
            (Uuid::new_v4(), None),
            SessionOrigin {
                ip: None,
                user_agent: None,
            },
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM iam_groups")
                .fetch_one(&pool)
                .await?,
            id
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM admin_action_logs")
                .fetch_one(&pool)
                .await?,
            0
        );
        Ok(())
    }
}
