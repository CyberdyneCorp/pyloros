use super::*;
use crate::{
    enrolled_factor::FactorDecision, passkey_ceremonies::SessionCeremony,
    passkey_credentials::authenticate,
};

pub(super) async fn verify(
    state: &Profile,
    id: &Identity,
    ceremony: &SessionCeremony<'_>,
    proof: Proof,
    challenge: Vec<u8>,
) -> Result<Response, sqlx::Error> {
    let mut tx = state.pool.begin().await?;
    let Ok(owner) = authenticate(
        &mut tx,
        proof.credential,
        &ceremony.transport(),
        challenge,
        Some(id.user),
    )
    .await?
    else {
        return Ok(finish::invalid());
    };
    // The assertion holds the account lock. Keep the session live through the proof write.
    let active: Option<Uuid> = sqlx::query_scalar(
        "SELECT s.id FROM sessions s JOIN users u ON u.id=s.user_id
         WHERE u.id=$1 AND s.id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
         AND (u.tokens_valid_after IS NULL OR $3>floor(extract(epoch FROM u.tokens_valid_after))::bigint)
         FOR SHARE OF s"
    ).bind(id.user).bind(ceremony.session).bind(id.iat).fetch_optional(&mut *tx).await?;
    if active.is_none() {
        return Ok(finish::invalid());
    }
    if owner.mfa {
        let Some(code) = proof.code else {
            return Ok(finish::invalid());
        };
        let Some(verifier) = &state.factor else {
            return Ok(internal());
        };
        match verifier.consume(&mut tx, id.user, &code, Utc::now()).await {
            Ok(FactorDecision::Totp | FactorDecision::RecoveryCode) => (),
            Ok(_) => return Ok(finish::invalid()),
            Err(_) => return Ok(internal()),
        }
    }
    sqlx::query(
        "INSERT INTO passkey_reauthentication (user_id,session_id,credential_id,verified_at)
         VALUES($1,$2,$3,clock_timestamp()) ON CONFLICT(user_id,session_id) DO UPDATE
         SET credential_id=excluded.credential_id, verified_at=excluded.verified_at",
    )
    .bind(id.user)
    .bind(ceremony.session)
    .bind(owner.key)
    .execute(&mut *tx)
    .await?;
    commit_response(
        tx,
        (
            StatusCode::NO_CONTENT,
            [(header::CACHE_CONTROL, "no-store")],
        ),
    )
    .await
}
