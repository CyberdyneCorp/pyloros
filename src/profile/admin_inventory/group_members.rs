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
    if let Err(error) = chain.submit_group_member(&mutation).await {
        return writes::preparation_error(&mutation, error);
    }
    finish(tx, user, group, add, actor, origin)
        .await
        .unwrap_or_else(|_| internal())
}

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
        sqlx::query(
            "INSERT INTO iam_group_members(group_id,identity_id) VALUES ($1,$2)
            ON CONFLICT(group_id,identity_id) DO NOTHING",
        )
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
