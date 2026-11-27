//! Verify a previously enrolled authenticator inside the session transaction.
use chrono::{DateTime, Utc};
use data_encoding::BASE32_NOPAD;
use ring::{
    aead, hkdf, hmac,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct FactorVerifier(aead::LessSafeKey);

#[derive(Debug, Eq, PartialEq)]
pub enum FactorDecision {
    Totp,
    RecoveryCode,
    InvalidCode,
    NoUser,
    Inactive,
    NotEnrolled,
}

#[derive(Debug, thiserror::Error)]
pub enum FactorError {
    #[error("invalid factor encryption key")]
    Key,
    #[error("invalid encrypted authenticator seed")]
    Seed,
    #[error("factor store unavailable")]
    Database(#[from] sqlx::Error),
}

impl FactorVerifier {
    pub fn new(master: &str) -> Result<Self, FactorError> {
        if master.is_empty() {
            return Err(FactorError::Key);
        }
        let extracted = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(master.as_bytes());
        let derived = extracted
            .expand(
                &[b"cyberdyne-auth:key-encryption-key:v1"],
                &aead::AES_256_GCM,
            )
            .map_err(|_| FactorError::Key)?;
        Ok(Self(aead::LessSafeKey::new(derived.into())))
    }

    fn seed(&self, encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, FactorError> {
        let (prefix, ciphertext) = encrypted.split_at_checked(12).ok_or(FactorError::Seed)?;
        let nonce =
            aead::Nonce::try_assume_unique_for_key(prefix).map_err(|_| FactorError::Seed)?;
        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        let plain = self
            .0
            .open_in_place(nonce, aead::Aad::empty(), &mut buffer)
            .map_err(|_| FactorError::Seed)?;
        plain.make_ascii_uppercase();
        let encoded = std::str::from_utf8(plain).map_err(|_| FactorError::Seed)?;
        let seed = BASE32_NOPAD
            .decode(encoded.trim_end_matches('=').as_bytes())
            .map_err(|_| FactorError::Seed)?;
        if seed.is_empty() {
            return Err(FactorError::Seed);
        }
        Ok(Zeroizing::new(seed))
    }

    pub(crate) fn pending_seed(&self) -> Result<(String, Vec<u8>), FactorError> {
        let random = SystemRandom::new();
        let mut seed = Zeroizing::new([0u8; 20]);
        random.fill(seed.as_mut()).map_err(|_| FactorError::Seed)?;
        let secret = BASE32_NOPAD.encode(seed.as_ref());
        let mut nonce = [0u8; 12];
        random.fill(&mut nonce).map_err(|_| FactorError::Seed)?;
        let mut ciphertext = secret.as_bytes().to_vec();
        self.0
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut ciphertext,
            )
            .map_err(|_| FactorError::Seed)?;
        let mut encrypted = nonce.to_vec();
        encrypted.extend(ciphertext);
        Ok((secret, encrypted))
    }

    pub(crate) fn timestep(
        &self,
        encrypted: &[u8],
        code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<i64>, FactorError> {
        Ok(matched_step(&self.seed(encrypted)?, code, now.timestamp()))
    }

    pub async fn consume(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user: Uuid,
        code: &str,
        now: DateTime<Utc>,
    ) -> Result<FactorDecision, FactorError> {
        use FactorDecision::*;
        let row = sqlx::query_as::<_, (bool, bool, Option<Vec<u8>>)>(
            "SELECT is_active, totp_enabled, totp_secret_encrypted FROM users WHERE id=$1 FOR UPDATE"
        ).bind(user).fetch_optional(&mut **tx).await?;
        let encrypted = match row {
            None => return Ok(NoUser),
            Some((false, _, _)) => return Ok(Inactive),
            Some((true, true, Some(blob))) => blob,
            _ => return Ok(NotEnrolled),
        };
        if let Some(step) = self.timestep(&encrypted, code, now)? {
            let updated = sqlx::query(
                "UPDATE users SET totp_last_used_step=$2 WHERE id=$1
                 AND (totp_last_used_step IS NULL OR totp_last_used_step<$2)",
            )
            .bind(user)
            .bind(step)
            .execute(&mut **tx)
            .await?;
            return Ok(if updated.rows_affected() == 1 {
                Totp
            } else {
                InvalidCode
            });
        }
        let normalized = Zeroizing::new(code.trim().to_lowercase().replace(' ', ""));
        let digest = format!("{:x}", Sha256::digest(normalized.as_bytes()));
        let updated = sqlx::query(
            "UPDATE mfa_recovery_codes SET used_at=$3 WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL"
        ).bind(user).bind(digest).bind(now).execute(&mut **tx).await?;
        Ok(if updated.rows_affected() == 1 {
            RecoveryCode
        } else {
            InvalidCode
        })
    }
}

fn matched_step(seed: &[u8], submitted: &str, timestamp: i64) -> Option<i64> {
    let code = submitted.trim().as_bytes();
    if code.len() != 6 || !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let current = timestamp.div_euclid(30);
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    [current, current - 1, current + 1]
        .into_iter()
        .find(|step| {
            let tag = hmac::sign(&key, &step.to_be_bytes());
            let bytes = tag.as_ref();
            let offset = usize::from(bytes[19] & 15);
            let value =
                u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
            let expected = format!("{:06}", value % 1_000_000);
            bool::from(expected.as_bytes().ct_eq(code))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_seeds_are_random_and_only_open_under_their_enrollment_key() {
        let factor = FactorVerifier::new("synthetic-test-key").unwrap();
        let (secret, encrypted) = factor.pending_seed().unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(
            BASE32_NOPAD.encode(&factor.seed(&encrypted).unwrap()),
            secret
        );
        let (next, _) = factor.pending_seed().unwrap();
        assert_ne!(secret, next);
        assert!(
            FactorVerifier::new("different-key")
                .unwrap()
                .seed(&encrypted)
                .is_err()
        );
    }

    #[test]
    fn authenticator_accepts_one_adjacent_step_in_each_direction() {
        // RFC 6238 SHA-1 test key at Unix time 59, truncated to six digits.
        let key = b"12345678901234567890";
        for timestamp in [29, 59, 89] {
            assert_eq!(matched_step(key, " 287082 ", timestamp), Some(1));
        }
        assert_eq!(matched_step(key, "287082", 90), None);
    }
}
