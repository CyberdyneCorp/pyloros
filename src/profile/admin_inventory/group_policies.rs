//! PostgreSQL storage for group policy attachments.
use super::*;
use crate::grant_response::SessionOrigin;

pub(super) async fn store(
    mut tx: Transaction<'_, Postgres>,
    group: Uuid,
    policy: Uuid,
    attach: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let action = if attach {
        let locked =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM iam_groups WHERE id=$1 FOR KEY SHARE")
                .bind(group)
                .fetch_optional(&mut *tx)
                .await?;
        if locked.is_none() {
            return Ok(delete_group::missing(group));
        }
        if !lock_policy(&mut tx, policy).await? {
            return Ok(writes::missing(policy));
        }
        sqlx::query(
            "INSERT INTO iam_group_policies(group_id,policy_id) VALUES($1,$2)
             ON CONFLICT (group_id,policy_id) DO NOTHING",
        )
        .bind(group)
        .bind(policy)
        .execute(&mut *tx)
        .await?;
        "iam.group.policy.attach"
    } else {
        sqlx::query("DELETE FROM iam_group_policies WHERE group_id=$1 AND policy_id=$2")
            .bind(group)
            .bind(policy)
            .execute(&mut *tx)
            .await?;
        "iam.group.policy.detach"
    };
    crate::admin_audit::append(
        &mut tx,
        action,
        Some(actor),
        ("iam_group", &group.to_string()),
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
