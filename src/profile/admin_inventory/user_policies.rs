//! Direct IAM policy assignments for an operator-selected user.
use super::*;
use crate::{
    chain_settings::{Chain, IamMutation},
    grant_response::SessionOrigin,
};

pub(super) async fn prepare_chain(
    chain: &Chain,
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    policy: Uuid,
    attach: bool,
) -> Response {
    let identity = match user_identity::chain_token(&mut tx, user).await {
        Ok(token) => token,
        Err(response) => return *response,
    };
    if tx.commit().await.is_err() {
        return internal();
    }
    writes::prepare_chain_write(
        chain,
        IamMutation::UserPolicy {
            identity,
            policy,
            attach,
        },
    )
    .await
}
pub(super) async fn store(
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    policy: Uuid,
    attach: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let identity = match user_identity::for_update(&mut tx, user).await {
        Ok(id) => id,
        Err(response) => return Ok(*response),
    };
    let action = if attach {
        if !group_policies::lock_policy(&mut tx, policy).await? {
            return Ok(writes::missing(policy));
        }
        sqlx::query(
            "INSERT INTO iam_identity_policies(identity_id,policy_id) VALUES($1,$2)
            ON CONFLICT(identity_id,policy_id) DO NOTHING",
        )
        .bind(identity)
        .bind(policy)
        .execute(&mut *tx)
        .await?;
        "iam.user.policy.attach"
    } else {
        sqlx::query("DELETE FROM iam_identity_policies WHERE identity_id=$1 AND policy_id=$2")
            .bind(identity)
            .bind(policy)
            .execute(&mut *tx)
            .await?;
        "iam.user.policy.detach"
    };
    crate::admin_audit::append(
        &mut tx,
        action,
        Some(actor),
        ("user", &user.to_string()),
        json!({"policy_id":policy}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn failed_audit_preserves_a_direct_grant() -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql(
            "CREATE TEMP TABLE users(id uuid primary key,extra_metadata jsonb);
             CREATE TEMP TABLE iam_identities(id uuid,user_id uuid,chain_token_id int,status text,transfer_mode text);
             CREATE TEMP TABLE iam_identity_policies(identity_id uuid,policy_id uuid);
             CREATE TEMP TABLE audit_chain_head(id int primary key,head_hash text);
             CREATE TEMP TABLE admin_action_logs(id uuid,action text CHECK(false),target_type text,target_id text,
                extra_metadata jsonb,ip_address inet,user_agent text,created_at timestamptz,prev_hash text,
                row_hash text,actor_user_id uuid,actor_email text);"
        ).execute(&pool).await?;
        let user = Uuid::new_v4();
        let identity = Uuid::new_v4();
        let policy = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES($1,'{}')")
            .bind(user)
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO iam_identities VALUES($1,$2,NULL,'active','soulbound')")
            .bind(identity)
            .bind(user)
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO iam_identity_policies VALUES($1,$2)")
            .bind(identity)
            .bind(policy)
            .execute(&pool)
            .await?;
        let failure = store(
            pool.begin().await?,
            user,
            policy,
            false,
            (Uuid::new_v4(), None),
            SessionOrigin {
                ip: None,
                user_agent: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            failure
                .as_database_error()
                .and_then(|e| e.code())
                .as_deref(),
            Some("23514")
        );
        assert_eq!(
            sqlx::query_as::<_, (Uuid, Uuid)>(
                "SELECT identity_id,policy_id FROM iam_identity_policies"
            )
            .fetch_one(&pool)
            .await?,
            (identity, policy)
        );
        Ok(())
    }
}
