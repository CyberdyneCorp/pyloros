use crate::{
    passkey_assertion::{self, AssertionError, StoredCredential},
    passkey_ceremonies::CeremonyBinding,
};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(crate) struct Owner {
    pub(crate) user: Uuid,
    pub(crate) key: Uuid,
    pub(crate) mfa: bool,
    pub(crate) email: Option<String>,
    pub(crate) organization: Option<Uuid>,
}

pub(crate) async fn authenticate(
    tx: &mut Transaction<'_, Postgres>,
    document: serde_json::Value,
    binding: &CeremonyBinding<'_>,
    challenge: Vec<u8>,
    expected_user: Option<Uuid>,
) -> Result<Result<Owner, AssertionError>, sqlx::Error> {
    let Some(credential) = document.get("id").and_then(|v| v.as_str()) else {
        return Ok(Err(AssertionError::Invalid));
    };
    // Lock the account before the credential, in the same order as enrollment and revocation.
    let account = sqlx::query_as::<_, (Uuid, bool, Option<String>, Option<Uuid>)>(
        "SELECT u.id,u.totp_enabled,u.primary_email,u.organization_id FROM users u JOIN passkeys p ON p.user_id=u.id
         WHERE p.rp_id=$1 AND p.credential_id=$2 AND u.is_active AND ($3::uuid IS NULL OR u.id=$3) FOR UPDATE OF u")
        .bind(binding.relying_party)
        .bind(credential)
        .bind(expected_user)
        .fetch_optional(&mut **tx)
        .await?;
    let Some((user, mfa, email, organization)) = account else {
        return Ok(Err(AssertionError::Invalid));
    };
    let entry = sqlx::query_as::<_, (Uuid, Vec<u8>, i64, bool, Vec<u8>)>(
        "SELECT p.id,p.public_key,p.sign_count,p.backup_eligible,h.handle FROM passkeys p JOIN passkey_handles h USING(user_id)
         WHERE p.user_id=$1 AND p.rp_id=$2 AND p.credential_id=$3 AND p.revoked_at IS NULL FOR UPDATE OF p")
        .bind(user)
        .bind(binding.relying_party)
        .bind(credential)
        .fetch_optional(&mut **tx)
        .await?;
    let Some((key, public_key, count, eligible, handle)) = entry else {
        return Ok(Err(AssertionError::Invalid));
    };
    let Ok(counter) = u32::try_from(count) else {
        return Ok(Err(AssertionError::Invalid));
    };
    let credential = credential.to_owned();
    let rp = binding.relying_party.to_owned();
    let origin = binding.origin.to_owned();
    let usage = tokio::task::spawn_blocking(move || {
        passkey_assertion::verify(
            &rp,
            &origin,
            &challenge,
            &StoredCredential {
                id: &credential,
                public_key: &public_key,
                user_handle: &handle,
                counter,
                backup_eligible: eligible,
            },
            document,
        )
    })
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let usage = match usage {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    sqlx::query(
        "UPDATE passkeys SET sign_count=$2,backed_up=$3,last_used_at=clock_timestamp() WHERE id=$1",
    )
    .bind(key)
    .bind(i64::from(usage.counter))
    .bind(usage.backed_up)
    .execute(&mut **tx)
    .await?;
    Ok(Ok(Owner {
        user,
        key,
        mfa,
        email,
        organization,
    }))
}

#[cfg(test)]
mod tests;
