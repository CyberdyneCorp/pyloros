//! PostgreSQL storage for group and role policy attachments.
use super::*;
use crate::grant_response::SessionOrigin;

#[derive(Clone, Copy)]
pub(super) enum Owner {
    Group(Uuid),
    Role(Uuid),
}

pub(super) async fn store(
    mut tx: Transaction<'_, Postgres>,
    owner: Owner,
    policy: Uuid,
    attach: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let (id, kind, lock, insert, delete, on_attach, on_detach) = match owner {
        Owner::Group(id) => (
            id,
            "iam_group",
            "SELECT id FROM iam_groups WHERE id=$1 FOR KEY SHARE",
            "INSERT INTO iam_group_policies(group_id,policy_id) VALUES($1,$2) ON CONFLICT (group_id,policy_id) DO NOTHING",
            "DELETE FROM iam_group_policies WHERE group_id=$1 AND policy_id=$2",
            "iam.group.policy.attach",
            "iam.group.policy.detach",
        ),
        Owner::Role(id) => (
            id,
            "iam_role",
            "SELECT id FROM iam_roles WHERE id=$1 FOR KEY SHARE",
            "INSERT INTO iam_role_policies(role_id,policy_id) VALUES($1,$2)",
            "DELETE FROM iam_role_policies WHERE role_id=$1 AND policy_id=$2",
            "iam.role.policy.attach",
            "iam.role.policy.detach",
        ),
    };
    let (statement, action) = if attach {
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
        (insert, on_attach)
    } else {
        (delete, on_detach)
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
        statements::policies(tx, Some(policy)).await?;
    }
    Ok(locked.is_some())
}
