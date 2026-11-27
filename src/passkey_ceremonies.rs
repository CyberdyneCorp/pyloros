//! PostgreSQL state shared by the two halves of passkey registration.
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub struct Enrollment<'a> {
    pub user: Uuid,
    pub session: Uuid,
    pub relying_party: &'a str,
    pub origin: &'a str,
    pub binding: &'a str,
    pub policy_digest: &'a str,
}

impl Enrollment<'_> {
    pub async fn issue(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        challenge: &[u8; 32],
        ttl_seconds: i64,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO passkey_ceremonies
                (id, purpose, user_id, session_id, rp_id, origin, binding_hash, policy, challenge, expires_at)
             VALUES ($1, 'register', $2, $3, $4, $5, $6, $7, $8,
                     statement_timestamp() + $9 * interval '1 second')",
        )
        .bind(id)
        .bind(self.user)
        .bind(self.session)
        .bind(self.relying_party)
        .bind(self.origin)
        .bind(self.binding_digest())
        .bind(self.policy_digest)
        .bind(challenge.as_slice())
        .bind(ttl_seconds as f64)
        .execute(&mut **tx)
        .await?;
        Ok(id)
    }

    /// Consume and commit before returning the challenge for proof verification.
    /// A later failure while saving the credential cannot make this challenge reusable.
    pub async fn claim(
        &self,
        mut tx: Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        let challenge = sqlx::query_scalar(
            "UPDATE passkey_ceremonies SET consumed_at = clock_timestamp()
             WHERE id = $1 AND purpose = 'register' AND user_id = $2 AND session_id = $3
               AND rp_id = $4 AND origin = $5 AND binding_hash = $6 AND policy = $7
               AND consumed_at IS NULL AND expires_at > clock_timestamp()
             RETURNING challenge",
        )
        .bind(id)
        .bind(self.user)
        .bind(self.session)
        .bind(self.relying_party)
        .bind(self.origin)
        .bind(self.binding_digest())
        .bind(self.policy_digest)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(challenge)
    }

    fn binding_digest(&self) -> String {
        format!("{:x}", Sha256::digest(self.binding))
    }
}
