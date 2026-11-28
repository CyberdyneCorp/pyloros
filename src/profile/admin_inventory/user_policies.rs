//! Direct IAM policy assignments for an operator-selected user.
use super::*;
use crate::{
    chain_settings::{Chain, IamMutation},
    grant_response::SessionOrigin,
};

pub(super) async fn write_chain(
    chain: &Chain,
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    policy: Uuid,
    attach: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Response {
    let identity = match user_identity::chain_token(&mut tx, user).await {
        Ok(token) => token,
        Err(response) => return *response,
    };
    if chain.lock_signer(&mut tx).await.is_err() {
        return internal();
    }
    let mutation = IamMutation::UserPolicy {
        identity,
        policy,
        attach,
    };
    if let Err(error) = chain.submit_mutation(&mutation).await {
        return writes::preparation_error(&mutation, error);
    }
    finish(tx, user, policy, attach, actor, origin)
        .await
        .unwrap_or_else(|_| internal())
}

const ATTACH_POLICY: &str = "INSERT INTO iam_identity_policies(identity_id,policy_id)
    SELECT $1::uuid,$2::uuid WHERE NOT EXISTS (
        SELECT 1 FROM iam_identity_policies WHERE identity_id=$1 AND policy_id=$2
    )";

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
    if attach {
        if !group_policies::lock_policy(&mut tx, policy).await? {
            return Ok(writes::missing(policy));
        }
        sqlx::query(ATTACH_POLICY)
            .bind(identity)
            .bind(policy)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query("DELETE FROM iam_identity_policies WHERE identity_id=$1 AND policy_id=$2")
            .bind(identity)
            .bind(policy)
            .execute(&mut *tx)
            .await?;
    }
    finish(tx, user, policy, attach, actor, origin).await
}

async fn finish(
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    policy: Uuid,
    attach: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let action = if attach {
        "iam.user.policy.attach"
    } else {
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
    async fn a_visible_direct_policy_link_skips_the_insert() -> sqlx::Result<()> {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql("CREATE TEMP TABLE iam_identity_policies(identity_id uuid,policy_id uuid,primary key(identity_id,policy_id));
            CREATE TEMP SEQUENCE attempts;
            CREATE FUNCTION pg_temp.count_insert() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN PERFORM nextval('pg_temp.attempts'); RETURN NEW; END $$;
            CREATE TRIGGER attempts BEFORE INSERT ON iam_identity_policies FOR EACH ROW EXECUTE FUNCTION pg_temp.count_insert()")
            .execute(&mut *tx).await?;
        let (identity, policy) = (Uuid::new_v4(), Uuid::new_v4());
        for changed in [1, 0] {
            let inserted = sqlx::query(ATTACH_POLICY)
                .bind(identity)
                .bind(policy)
                .execute(&mut *tx)
                .await?;
            assert_eq!(inserted.rows_affected(), changed);
        }
        let attempts: i64 = sqlx::query_scalar("SELECT last_value FROM pg_temp.attempts")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(attempts, 1);
        tx.rollback().await
    }

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
                row_hash text,actor_user_id uuid,actor_type text,actor_client_id text,actor_email text);"
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
