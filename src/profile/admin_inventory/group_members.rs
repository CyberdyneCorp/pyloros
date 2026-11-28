//! Audited changes to ordinary IAM group memberships.
use super::*;
use crate::{
    chain_settings::{Chain, IamMutation, PrepareError},
    grant_response::SessionOrigin,
};

pub(super) async fn write_chain(
    chain: &Chain,
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    group: Uuid,
    add: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Response {
    match chain.check_group_namespace(group).await {
        Ok(()) => {}
        Err(PrepareError::ProtectedGroup) => return delete_group::protected(),
        Err(PrepareError::Catalog(error)) => return admin_client_roles::chain_error(error),
        Err(_) => return internal(),
    }
    let identity = match user_identity::chain_token(&mut tx, user).await {
        Ok(token) => token,
        Err(error) => return *error,
    };
    if chain.lock_signer(&mut tx).await.is_err() {
        return internal();
    }
    let mutation = IamMutation::GroupMember {
        group,
        identity,
        add,
    };
    if let Err(error) = chain.submit_mutation(&mutation).await {
        return writes::preparation_error(&mutation, error);
    }
    finish(tx, user, group, add, actor, origin)
        .await
        .unwrap_or_else(|_| internal())
}

// Decide whether to add from the statement snapshot shared by both writer versions.
const ADD_MEMBER: &str = "INSERT INTO iam_group_members(group_id,identity_id)
    SELECT $1::uuid,$2::uuid WHERE NOT EXISTS (
        SELECT 1 FROM iam_group_members WHERE group_id=$1 AND identity_id=$2
    )";

pub(super) async fn store(
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    group: Uuid,
    add: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    // A concurrent rename must finish before deciding whether this is a client role.
    let name = sqlx::query_scalar::<_, String>("SELECT name FROM iam_groups WHERE id=$1 FOR SHARE")
        .bind(group)
        .fetch_optional(&mut *tx)
        .await?;
    if name.as_deref().is_some_and(|name| name.starts_with("rp:")) {
        return Ok(delete_group::protected());
    }
    let identity = match user_identity::for_update(&mut tx, user).await {
        Ok(id) => id,
        Err(response) => return Ok(*response),
    };
    if add {
        if name.is_none() {
            return Ok(delete_group::missing(group));
        }
        sqlx::query(ADD_MEMBER)
            .bind(group)
            .bind(identity)
            .execute(&mut *tx)
            .await?;
    } else if name.is_some() {
        sqlx::query("DELETE FROM iam_group_members WHERE group_id=$1 AND identity_id=$2")
            .bind(group)
            .bind(identity)
            .execute(&mut *tx)
            .await?;
    }
    finish(tx, user, group, add, actor, origin).await
}

async fn finish(
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    group: Uuid,
    add: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let action = if add {
        "iam.user.group.add"
    } else {
        "iam.user.group.remove"
    };
    crate::admin_audit::append(
        &mut tx,
        action,
        Some(actor),
        ("user", &user.to_string()),
        json!({"group_id":group}),
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
    async fn add_observes_membership_before_a_pending_removal() -> Result<(), sqlx::Error> {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let schema = format!("membership_{}", Uuid::new_v4().simple());
        let path = format!("SET LOCAL search_path TO {schema}");
        let group = Uuid::new_v4();
        let identity = Uuid::new_v4();
        let mut setup = pool.begin().await?;
        sqlx::raw_sql(&format!("CREATE SCHEMA {schema}; {path};
            CREATE TABLE iam_group_members(group_id uuid,identity_id uuid, PRIMARY KEY(group_id,identity_id))"))
            .execute(&mut *setup).await?;
        sqlx::query(ADD_MEMBER)
            .bind(group)
            .bind(identity)
            .execute(&mut *setup)
            .await?;
        setup.commit().await?;
        let mut remover = pool.begin().await?;
        sqlx::query(&path).execute(&mut *remover).await?;
        sqlx::query("DELETE FROM iam_group_members")
            .execute(&mut *remover)
            .await?;
        let mut adder = pool.begin().await?;
        sqlx::raw_sql(&format!("{path}; SET LOCAL lock_timeout='1s'"))
            .execute(&mut *adder)
            .await?;
        let repeated = sqlx::query(ADD_MEMBER)
            .bind(group)
            .bind(identity)
            .execute(&mut *adder)
            .await;
        adder.rollback().await?;
        remover.commit().await?;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await?;
        assert_eq!(repeated?.rows_affected(), 0);
        Ok(())
    }
}
