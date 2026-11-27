//! PostgreSQL state shared by the two halves of passkey ceremonies.
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

pub struct CeremonyBinding<'a> {
    pub relying_party: &'a str,
    pub origin: &'a str,
    pub binding: &'a str,
    pub policy_digest: &'a str,
}

impl Enrollment<'_> {
    fn transport(&self) -> CeremonyBinding<'_> {
        CeremonyBinding {
            relying_party: self.relying_party,
            origin: self.origin,
            binding: self.binding,
            policy_digest: self.policy_digest,
        }
    }

    pub async fn issue(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        challenge: &[u8; 32],
        ttl_seconds: i64,
    ) -> Result<Uuid, sqlx::Error> {
        self.transport()
            .insert(tx, Some((self.user, self.session)), challenge, ttl_seconds)
            .await
    }

    pub async fn claim(
        &self,
        tx: Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        self.transport()
            .consume(tx, Some((self.user, self.session)), id)
            .await
    }
}

impl CeremonyBinding<'_> {
    pub async fn issue_login(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        challenge: &[u8; 32],
        ttl_seconds: i64,
    ) -> Result<Uuid, sqlx::Error> {
        self.insert(tx, None, challenge, ttl_seconds).await
    }

    pub async fn claim_login(
        &self,
        tx: Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        self.consume(tx, None, id).await
    }

    async fn insert(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        account: Option<(Uuid, Uuid)>,
        challenge: &[u8; 32],
        ttl_seconds: i64,
    ) -> Result<Uuid, sqlx::Error> {
        let purpose = if account.is_some() {
            "register"
        } else {
            "login"
        };
        let (user, session) = account.unzip();
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO passkey_ceremonies
                (id, purpose, user_id, session_id, rp_id, origin, binding_hash, policy, challenge, expires_at)
             VALUES ($1, $10, $2, $3, $4, $5, $6, $7, $8,
                     statement_timestamp() + $9 * interval '1 second')",
        )
        .bind(id)
        .bind(user)
        .bind(session)
        .bind(self.relying_party)
        .bind(self.origin)
        .bind(self.binding_digest())
        .bind(self.policy_digest)
        .bind(challenge.as_slice())
        .bind(ttl_seconds as f64)
        .bind(purpose)
        .execute(&mut **tx)
        .await?;
        Ok(id)
    }

    /// Consume and commit before returning the challenge for proof verification.
    /// A later failure while saving the credential cannot make this challenge reusable.
    async fn consume(
        &self,
        mut tx: Transaction<'_, Postgres>,
        account: Option<(Uuid, Uuid)>,
        id: Uuid,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        let purpose = if account.is_some() {
            "register"
        } else {
            "login"
        };
        let (user, session) = account.unzip();
        let challenge = sqlx::query_scalar(
            "UPDATE passkey_ceremonies SET consumed_at = clock_timestamp()
             WHERE id = $1 AND purpose = $8 AND user_id IS NOT DISTINCT FROM $2 AND session_id IS NOT DISTINCT FROM $3
               AND rp_id = $4 AND origin = $5 AND binding_hash = $6 AND policy = $7
               AND consumed_at IS NULL AND expires_at > clock_timestamp()
             RETURNING challenge",
        )
        .bind(id)
        .bind(user)
        .bind(session)
        .bind(self.relying_party)
        .bind(self.origin)
        .bind(self.binding_digest())
        .bind(self.policy_digest)
        .bind(purpose)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(challenge)
    }

    fn binding_digest(&self) -> String {
        format!("{:x}", Sha256::digest(self.binding))
    }
}
