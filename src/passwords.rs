//! Password verification for the credential step of first-party sign-in.
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use std::str::FromStr;
use tokio::{sync::Semaphore, task::JoinError};

// Retain the permit inside the worker even when the requesting task is cancelled.
static HASH_JOBS: Semaphore = Semaphore::const_new(2);

pub(crate) async fn verify_on_worker(
    check: impl FnOnce() -> bool + Send + 'static,
) -> Result<bool, JoinError> {
    let permit = HASH_JOBS.acquire().await.expect("hash queue stays open");
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        check()
    })
    .await
}

pub(crate) fn matches_argon2(secret: &[u8], encoded: &str) -> bool {
    PasswordHash::new(encoded)
        .is_ok_and(|hash| Argon2::default().verify_password(secret, &hash).is_ok())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PasswordScheme {
    #[default]
    Argon2,
    Bcrypt,
}

impl FromStr for PasswordScheme {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "argon2" => Ok(Self::Argon2),
            "bcrypt" => Ok(Self::Bcrypt),
            _ => Err("unsupported password scheme"),
        }
    }
}

impl PasswordScheme {
    /// An absent hash still incurs the standard verification work for this scheme.
    pub async fn verify(self, password: String, stored: Option<String>) -> Result<bool, JoinError> {
        verify_on_worker(move || {
            let encoded = stored.as_deref().unwrap_or(self.dummy());
            self.matches(&password, encoded) && stored.is_some()
        })
        .await
    }

    fn matches(self, password: &str, encoded: &str) -> bool {
        if password.chars().count() > 4096 {
            return false;
        }
        match self {
            Self::Argon2 => matches_argon2(password.as_bytes(), encoded),
            Self::Bcrypt => matches_bcrypt(password, encoded),
        }
    }

    fn dummy(self) -> &'static str {
        match self {
            Self::Argon2 => {
                "$argon2id$v=19$m=65536,t=3,p=4$aw0B4HyPUerdGwPgfA+h1A$d/1sj8ptTl6SDW3nPDUKN15OZEO/1oP4+GlEQXQvOBw"
            }
            Self::Bcrypt => "$2b$12$PxOdJiOftk1JTWfTw.oM6eHThRrrKgnRcIDnDF3MEgZyS/qFh6b4K",
        }
    }
}

fn matches_bcrypt(password: &str, encoded: &str) -> bool {
    if password.contains('\0') || encoded.starts_with("$2x$") {
        return false;
    }
    if let Some(legacy) = encoded.strip_prefix("$2$") {
        // Original bcrypt cycled the password bytes without a terminating NUL.
        let key: Vec<u8> = password.bytes().cycle().take(72).collect();
        return bcrypt::verify(key, &format!("$2a${legacy}")).unwrap_or(false);
    }
    bcrypt::verify(password, encoded).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn existing_hashes_and_missing_credentials() {
        let password = "pyloros fixture π";
        for scheme in [PasswordScheme::Argon2, PasswordScheme::Bcrypt] {
            let stored = scheme.dummy();
            assert!(
                scheme
                    .verify(password.into(), Some(stored.into()))
                    .await
                    .unwrap()
            );
            assert!(!scheme.verify(password.into(), None).await.unwrap());
            assert!(!scheme.matches("incorrect", stored));
            assert!(!scheme.matches(password, "malformed"));
        }
        assert!(!PasswordScheme::Argon2.matches(password, PasswordScheme::Bcrypt.dummy()));
        assert!(!PasswordScheme::Bcrypt.matches(password, PasswordScheme::Argon2.dummy()));
    }

    #[test]
    fn original_bcrypt_verifies_empty_and_multibyte_inputs() {
        assert!(matches_bcrypt(
            "",
            "$2$04$XnUefHEpysTVrmREA7oOOeuw50Ono7ynxxD7trRA1F8cepot.pOXO"
        ));
        assert!(matches_bcrypt(
            "unicode π",
            "$2$04$nK6rieB8W.Z.qDHk0LpMOeoNFtwAU1a1LZ/L0GRjhebBmFcOt.IeK"
        ));
    }

    #[test]
    fn legacy_bcrypt_uses_utf8_bytes_at_the_truncation_boundary() {
        let encoded = "$2b$12$QVXM9WCcLILYhN1cAqDJOuRzYVRPFuM7OCV0CisQyPUTjwc1SjzzG";
        let prefix = "a".repeat(71);
        assert!(PasswordScheme::Bcrypt.matches(&format!("{prefix}bé"), encoded));
        assert!(PasswordScheme::Bcrypt.matches(&format!("{prefix}bX"), encoded));
        assert!(!PasswordScheme::Bcrypt.matches(&format!("{prefix}b\0"), encoded));
    }
}
