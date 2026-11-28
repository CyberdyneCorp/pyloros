//! Persist and audit operator policy attachments.
use super::*;
use crate::{
    chain_settings::{Chain, IamMutation},
    grant_response::SessionOrigin,
};

#[derive(Clone, Copy)]
pub(super) enum Owner {
    Group(Uuid),
    Role(Uuid),
}

pub(super) async fn write_chain(
    chain: &Chain,
    mut tx: Transaction<'_, Postgres>,
    group: Uuid,
    policy: Uuid,
    attach: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Response {
    if chain.lock_signer(&mut tx).await.is_err() {
        return internal();
    }
    let mutation = IamMutation::GroupPolicy {
        group,
        policy,
        attach,
    };
    if let Err(error) = chain.submit_mutation(&mutation).await {
        return writes::preparation_error(&mutation, error);
    }
    finish(tx, Owner::Group(group), policy, attach, actor, origin)
        .await
        .unwrap_or_else(|_| internal())
}

const ATTACH_GROUP_POLICY: &str = "INSERT INTO iam_group_policies(group_id,policy_id)
    SELECT $1::uuid,$2::uuid WHERE NOT EXISTS (
        SELECT 1 FROM iam_group_policies WHERE group_id=$1 AND policy_id=$2
    )";

pub(super) async fn store(
    mut tx: Transaction<'_, Postgres>,
    owner: Owner,
    policy: Uuid,
    attach: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let (id, lock, insert, delete) = match owner {
        Owner::Group(id) => (
            id,
            "SELECT id FROM iam_groups WHERE id=$1 FOR KEY SHARE",
            ATTACH_GROUP_POLICY,
            "DELETE FROM iam_group_policies WHERE group_id=$1 AND policy_id=$2",
        ),
        Owner::Role(id) => (
            id,
            "SELECT id FROM iam_roles WHERE id=$1 FOR KEY SHARE",
            "INSERT INTO iam_role_policies(role_id,policy_id) VALUES($1,$2)",
            "DELETE FROM iam_role_policies WHERE role_id=$1 AND policy_id=$2",
        ),
    };
    let statement = if attach {
        let locked = sqlx::query_scalar::<_, Uuid>(lock)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        if locked.is_none() {
            return Ok(match owner {
                Owner::Group(id) => delete_group::missing(id),
                Owner::Role(id) => assume_role::missing(id),
            });
        }
        if !lock_policy(&mut tx, policy).await? {
            return Ok(writes::missing(policy));
        }
        insert
    } else {
        delete
    };
    // A repeated role attachment succeeds. Concurrent first inserts compete on the pair key.
    let exists = if matches!(owner, Owner::Role(_)) && attach {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM iam_role_policies WHERE role_id=$1 AND policy_id=$2)",
        )
        .bind(id)
        .bind(policy)
        .fetch_one(&mut *tx)
        .await?
    } else {
        false
    };
    if !exists {
        sqlx::query(statement)
            .bind(id)
            .bind(policy)
            .execute(&mut *tx)
            .await?;
    }
    finish(tx, owner, policy, attach, actor, origin).await
}

async fn finish(
    mut tx: Transaction<'_, Postgres>,
    owner: Owner,
    policy: Uuid,
    attach: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let (id, kind, action) = match (owner, attach) {
        (Owner::Group(id), true) => (id, "iam_group", "iam.group.policy.attach"),
        (Owner::Group(id), false) => (id, "iam_group", "iam.group.policy.detach"),
        (Owner::Role(id), true) => (id, "iam_role", "iam.role.policy.attach"),
        (Owner::Role(id), false) => (id, "iam_role", "iam.role.policy.detach"),
    };
    crate::admin_audit::append(
        &mut tx,
        action,
        Some(actor),
        (kind, &id.to_string()),
        json!({"policy_id":policy}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})).into_response())
}

pub(super) async fn lock_policy(
    tx: &mut Transaction<'_, Postgres>,
    policy: Uuid,
) -> Result<bool, sqlx::Error> {
    let locked =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM iam_policies WHERE id=$1 FOR KEY SHARE")
            .bind(policy)
            .fetch_optional(&mut **tx)
            .await?;
    if locked.is_some() {
        statements::validate_stored_policy(tx, policy).await?;
    }
    Ok(locked.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_visible_group_policy_link_skips_the_insert() -> sqlx::Result<()> {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql("CREATE TEMP TABLE iam_group_policies(group_id uuid,policy_id uuid,primary key(group_id,policy_id));
            CREATE TEMP SEQUENCE attempts;
            CREATE FUNCTION pg_temp.count_insert() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN PERFORM nextval('pg_temp.attempts'); RETURN NEW; END $$;
            CREATE TRIGGER attempts BEFORE INSERT ON iam_group_policies FOR EACH ROW EXECUTE FUNCTION pg_temp.count_insert()")
            .execute(&mut *tx).await?;
        let (group, policy) = (Uuid::new_v4(), Uuid::new_v4());
        for changed in [1, 0] {
            let inserted = sqlx::query(ATTACH_GROUP_POLICY)
                .bind(group)
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
    async fn attachment_validates_stored_rules_before_linking() -> sqlx::Result<()> {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(
            "CREATE TEMP TABLE iam_policies(id uuid primary key,name text,description text,version int,
                is_active bool,chain_policy_id int,created_at timestamptz default now());
             CREATE TEMP TABLE iam_policy_statements(id uuid,policy_id uuid,sid text,effect text,
                actions jsonb,resources jsonb,conditions jsonb,sort_order int);",
        ).execute(&mut *tx).await?;
        let policy = Uuid::new_v4();
        sqlx::query("INSERT INTO iam_policies(id) VALUES($1)")
            .bind(policy)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO iam_policy_statements(policy_id,effect,actions,resources,conditions)
                     VALUES($1,'allow','[17]','[]','[]')",
        )
        .bind(policy)
        .execute(&mut *tx)
        .await?;
        assert!(lock_policy(&mut tx, policy).await?);
        sqlx::query("UPDATE iam_policy_statements SET actions='17'")
            .execute(&mut *tx)
            .await?;
        assert!(matches!(
            lock_policy(&mut tx, policy).await,
            Err(sqlx::Error::Decode(_))
        ));
        tx.rollback().await
    }
}
