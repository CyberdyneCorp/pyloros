//! Resolve existing IAM identities for operator writes.
use super::*;
use crate::login_http::problem;

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

pub(super) fn validate_identity(status: &str, mode: &str) -> Result<(), sqlx::Error> {
    if matches!(status, "active" | "suspended" | "revoked")
        && matches!(mode, "soulbound" | "transferable" | "restricted")
    {
        Ok(())
    } else {
        Err(sqlx::Error::Decode("invalid stored IAM identity".into()))
    }
}

pub(super) async fn for_update(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Uuid, Box<Response>> {
    let metadata = sqlx::query_scalar::<_, String>(
        "SELECT extra_metadata::text FROM users WHERE id=$1 FOR KEY SHARE",
    )
    .bind(user)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| Box::new(internal()))?
    .ok_or_else(|| Box::new(problem(StatusCode::NOT_FOUND, &user.to_string())))?;
    admin_organizations::normalized_storage(&metadata).map_err(|_| Box::new(internal()))?;
    identity(tx, user)
        .await
        .map_err(|_| Box::new(internal()))?
        .map(|record| record.id)
        .ok_or_else(|| Box::new(problem(StatusCode::BAD_REQUEST, &user.to_string())))
}

pub(super) async fn chain_token(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<u32, Box<Response>> {
    let record = identity(tx, user).await.map_err(|_| Box::new(internal()))?;
    let token = record.and_then(|r| r.chain_token_id).ok_or_else(|| {
        Box::new(problem(
            StatusCode::BAD_REQUEST,
            &format!("user {user} has no chain identity"),
        ))
    })?;
    u32::try_from(token).map_err(|_| Box::new(internal()))
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
