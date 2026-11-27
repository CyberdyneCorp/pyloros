//! Audited changes to ordinary IAM group memberships.
use super::*;
use crate::{
    chain_settings::{Chain, IamMutation, PrepareError},
    grant_response::SessionOrigin,
    login_http::problem,
};

struct Identity {
    id: Uuid,
    chain_token_id: Option<i32>,
}

async fn identity(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Option<Identity>, sqlx::Error> {
    let row = sqlx::query_as::<_, (Uuid, Option<i32>, String, String)>(
        "SELECT id, chain_token_id, status, transfer_mode FROM iam_identities
         WHERE user_id=$1 FOR KEY SHARE",
    )
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((id, chain_token_id, status, mode)) = row else {
        return Ok(None);
    };
    validate_identity(&status, &mode)?;
    Ok(Some(Identity { id, chain_token_id }))
}

fn validate_identity(status: &str, mode: &str) -> Result<(), sqlx::Error> {
    if matches!(status, "active" | "suspended" | "revoked")
        && matches!(mode, "soulbound" | "transferable" | "restricted")
    {
        Ok(())
    } else {
        Err(sqlx::Error::Decode("invalid stored IAM identity".into()))
    }
}

pub(super) async fn prepare_chain(
    chain: &Chain,
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    group: Uuid,
    add: bool,
) -> Response {
    match chain.check_group_namespace(group).await {
        Ok(()) => {}
        Err(PrepareError::ProtectedGroup) => return delete_group::protected(),
        Err(PrepareError::Catalog(error)) => return admin_client_roles::chain_error(error),
        Err(_) => return internal(),
    }
    let Ok(record) = identity(&mut tx, user).await else {
        return internal();
    };
    let Some(token) = record.and_then(|record| record.chain_token_id) else {
        return problem(
            StatusCode::BAD_REQUEST,
            &format!("user {user} has no chain identity"),
        );
    };
    let Ok(identity) = u32::try_from(token) else {
        return internal();
    };
    if tx.commit().await.is_err() {
        return internal();
    }
    writes::prepare_chain_write(
        chain,
        IamMutation::GroupMember {
            group,
            identity,
            add,
        },
    )
    .await
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
    let account = sqlx::query_scalar::<_, String>(
        "SELECT extra_metadata::text FROM users WHERE id=$1 FOR KEY SHARE",
    )
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(metadata) = account else {
        return Ok(problem(StatusCode::NOT_FOUND, &user.to_string()));
    };
    admin_organizations::normalized_storage(&metadata)?;
    let Some(identity) = identity(&mut tx, user).await? else {
        return Ok(problem(StatusCode::BAD_REQUEST, &user.to_string()));
    };
    let action = if add {
        if name.is_none() {
            return Ok(delete_group::missing(group));
        }
        sqlx::query(
            "INSERT INTO iam_group_members(group_id,identity_id) VALUES ($1,$2)
            ON CONFLICT(group_id,identity_id) DO NOTHING",
        )
        .bind(group)
        .bind(identity.id)
        .execute(&mut *tx)
        .await?;
        "iam.user.group.add"
    } else {
        if name.is_some() {
            sqlx::query("DELETE FROM iam_group_members WHERE group_id=$1 AND identity_id=$2")
                .bind(group)
                .bind(identity.id)
                .execute(&mut *tx)
                .await?;
        }
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
    #[test]
    fn historical_identity_states_and_transfer_modes_are_validated_before_a_membership_write() {
        assert!(validate_identity("suspended", "restricted").is_ok());
        assert!(validate_identity("retired", "soulbound").is_err());
        assert!(validate_identity("revoked", "legacy").is_err());
    }
}
