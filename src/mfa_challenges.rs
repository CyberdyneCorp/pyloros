//! Typed credentials for continuing login with a second factor.
use crate::signing::SigningIdentity;
use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Binding {
    Password,
    Passkey { passkey: Uuid, ceremony: Uuid },
    EmailLink(Uuid),
}

#[derive(Debug, Eq, PartialEq)]
pub struct Challenge {
    pub user: Uuid,
    pub id: Uuid,
    pub expires: DateTime<Utc>,
    pub binding: Binding,
}

#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    #[error("invalid MFA challenge lifetime")]
    Lifetime,
    #[error("invalid MFA credential")]
    Invalid,
    #[error("JWT processing failed")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl ChallengeError {
    pub(crate) fn audit_reason(&self) -> &'static str {
        match self {
            Self::Jwt(error)
                if matches!(
                    error.kind(),
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature
                ) =>
            {
                "expired"
            }
            _ => "invalid_token",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: Uuid,
    jti: Uuid,
    #[serde(rename = "type")]
    kind: String,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    passkey_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ceremony_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    magic_link_id: Option<Uuid>,
}

impl SigningIdentity {
    pub fn issue_mfa(
        &self,
        user: Uuid,
        binding: Binding,
        now: DateTime<Utc>,
        lifetime: TimeDelta,
    ) -> Result<String, ChallengeError> {
        if lifetime.num_seconds() < 1 {
            return Err(ChallengeError::Lifetime);
        }
        let expires = now
            .checked_add_signed(lifetime)
            .ok_or(ChallengeError::Lifetime)?;
        let (passkey_id, ceremony_id, magic_link_id) = match binding {
            Binding::Password => (None, None, None),
            Binding::Passkey { passkey, ceremony } => (Some(passkey), Some(ceremony), None),
            Binding::EmailLink(id) => (None, None, Some(id)),
        };
        Ok(self.sign(&Claims {
            iss: self.issuer().into(),
            sub: user,
            jti: Uuid::new_v4(),
            kind: "mfa".into(),
            iat: now.timestamp(),
            exp: expires.timestamp(),
            passkey_id,
            ceremony_id,
            magic_link_id,
        })?)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RefreshIdentity {
    pub user: Uuid,
    pub session: Uuid,
    pub jti: Uuid,
}

pub(crate) struct AccessRevocation {
    pub jti: Uuid,
    pub expires: DateTime<Utc>,
    pub client: Option<String>,
}

pub struct ChallengeVerifier {
    key: DecodingKey,
    validation: Validation,
}

impl ChallengeVerifier {
    pub fn rsa(issuer: &str, pem: &[u8]) -> Result<Self, ChallengeError> {
        Ok(Self::new(
            issuer,
            Algorithm::RS256,
            DecodingKey::from_rsa_pem(pem)?,
        ))
    }

    pub fn hmac(issuer: &str, secret: &[u8]) -> Result<Self, ChallengeError> {
        if secret.is_empty() {
            return Err(ChallengeError::Invalid);
        }
        Ok(Self::new(
            issuer,
            Algorithm::HS256,
            DecodingKey::from_secret(secret),
        ))
    }

    fn new(issuer: &str, alg: Algorithm, key: DecodingKey) -> Self {
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[issuer]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.validate_aud = false;
        Self { key, validation }
    }

    pub(crate) fn verified_claims(
        &self,
        token: &str,
    ) -> jsonwebtoken::errors::Result<serde_json::Value> {
        Ok(decode(token, &self.key, &self.validation)?.claims)
    }

    pub(crate) fn logout_client_hint(&self, token: &str) -> Option<String> {
        #[derive(Deserialize)]
        struct Hint {
            #[serde(rename = "sub")]
            _subject: Uuid,
            aud: String,
            #[serde(rename = "type")]
            kind: Option<serde_json::Value>,
        }
        let mut validation = self.validation.clone();
        validation.validate_exp = false;
        validation.set_required_spec_claims(&["iss", "sub"]);
        let hint = decode::<Hint>(token, &self.key, &validation).ok()?.claims;
        (hint.kind.is_none() && !hint.aud.is_empty()).then_some(hint.aud)
    }

    pub(crate) fn revocable_access(&self, token: &str) -> Option<AccessRevocation> {
        #[derive(Deserialize)]
        struct Claims {
            #[serde(rename = "iss")]
            _issuer: String,
            #[serde(rename = "sub")]
            _user: Uuid,
            #[serde(rename = "sid")]
            _session: Option<Uuid>,
            #[serde(rename = "type")]
            kind: String,
            jti: Uuid,
            exp: i64,
            client_id: Option<String>,
        }
        let claims = decode::<Claims>(token, &self.key, &self.validation)
            .ok()?
            .claims;
        if claims.kind != "access" {
            return None;
        }
        Some(AccessRevocation {
            jti: claims.jti,
            expires: DateTime::from_timestamp(claims.exp, 0)?,
            client: claims.client_id,
        })
    }

    pub(crate) fn refresh(&self, token: &str) -> Result<RefreshIdentity, ChallengeError> {
        #[derive(Deserialize)]
        struct Claims {
            #[serde(rename = "iss")]
            _issuer: String,
            sub: Uuid,
            sid: Uuid,
            jti: Uuid,
            #[serde(rename = "type")]
            kind: String,
        }
        let claims = decode::<Claims>(token, &self.key, &self.validation)?.claims;
        if claims.kind != "refresh" {
            return Err(ChallengeError::Invalid);
        }
        Ok(RefreshIdentity {
            user: claims.sub,
            session: claims.sid,
            jti: claims.jti,
        })
    }

    pub fn verify(&self, token: &str) -> Result<Challenge, ChallengeError> {
        let claims = decode::<Claims>(token, &self.key, &self.validation)?.claims;
        if claims.kind != "mfa" || claims.exp <= claims.iat {
            return Err(ChallengeError::Invalid);
        }
        let binding = match (claims.passkey_id, claims.ceremony_id, claims.magic_link_id) {
            (None, None, None) => Binding::Password,
            (None, None, Some(id)) => Binding::EmailLink(id),
            (Some(passkey), Some(ceremony), None) => Binding::Passkey { passkey, ceremony },
            _ => return Err(ChallengeError::Invalid),
        };
        Ok(Challenge {
            user: claims.sub,
            id: claims.jti,
            binding,
            expires: DateTime::from_timestamp(claims.exp, 0).ok_or(ChallengeError::Lifetime)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn logout_hint_accepts_historical_id_tokens_only_for_the_expected_issuer() {
        let signer = SigningIdentity::hmac("issuer".into(), b"test-secret").unwrap();
        let verifier = ChallengeVerifier::hmac("issuer", b"test-secret").unwrap();
        let hint = json!({"iss":"issuer","sub":Uuid::new_v4(),"aud":"client","exp":1});
        assert_eq!(
            verifier
                .logout_client_hint(&signer.sign(&hint).unwrap())
                .as_deref(),
            Some("client")
        );
        for (field, value) in [
            ("iss", json!("another")),
            ("type", json!("access")),
            ("aud", json!(["client"])),
            ("sub", json!("invalid")),
        ] {
            let mut invalid = hint.clone();
            invalid[field] = value;
            assert!(
                verifier
                    .logout_client_hint(&signer.sign(&invalid).unwrap())
                    .is_none()
            );
        }
    }

    #[test]
    fn logout_accepts_client_access_tokens_and_rejects_other_credential_types() {
        let signer = SigningIdentity::hmac("issuer".into(), b"test-secret").unwrap();
        let verifier = ChallengeVerifier::hmac("issuer", b"test-secret").unwrap();
        let jti = Uuid::new_v4();
        let exp = Utc::now().timestamp() + 120;
        let mut claims = json!({"iss":"issuer","sub":Uuid::new_v4(),"jti":jti,"exp":exp,"type":"access","client_id":"registered"});
        let token = verifier
            .revocable_access(&signer.sign(&claims).unwrap())
            .unwrap();
        assert_eq!(token.jti, jti);
        assert_eq!(token.expires.timestamp(), exp);
        assert_eq!(token.client.as_deref(), Some("registered"));
        claims["type"] = json!("refresh");
        assert!(
            verifier
                .revocable_access(&signer.sign(&claims).unwrap())
                .is_none()
        );
    }

    #[test]
    fn refresh_requires_the_configured_issuer_and_a_session_credential() {
        let signer = SigningIdentity::hmac("issuer".into(), b"test-secret").unwrap();
        let verifier = ChallengeVerifier::hmac("issuer", b"test-secret").unwrap();
        let valid = json!({"iss":"issuer","sub":Uuid::new_v4(),"sid":Uuid::new_v4(),
            "jti":Uuid::new_v4(),"exp":Utc::now().timestamp()+300,"type":"refresh"});
        assert!(verifier.refresh(&signer.sign(&valid).unwrap()).is_ok());
        for field in ["iss", "sub", "sid", "jti", "exp", "type"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(verifier.refresh(&signer.sign(&missing).unwrap()).is_err());
        }
        for (field, value) in [
            ("iss", "another-issuer"),
            ("type", "access"),
            ("type", "mfa"),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = json!(value);
            assert!(verifier.refresh(&signer.sign(&invalid).unwrap()).is_err());
        }
    }

    #[test]
    fn refuses_unsigned_context_changes_and_non_challenge_credentials() {
        let signer = SigningIdentity::hmac("issuer".into(), b"test-secret").unwrap();
        let verifier = ChallengeVerifier::hmac("issuer", b"test-secret").unwrap();
        let now = Utc::now();
        let valid = json!({"iss":"issuer","sub":Uuid::new_v4(),"jti":Uuid::new_v4(),
            "iat":now.timestamp(),"exp":now.timestamp()+300,"type":"mfa"});
        let id = json!(Uuid::new_v4());
        for (field, value) in [
            ("type", json!("access")),
            ("type", json!("refresh")),
            ("iss", json!("other")),
            ("exp", json!(0)),
            ("sub", json!("invalid")),
            ("passkey_id", id.clone()),
            ("ceremony_id", id.clone()),
        ] {
            let mut claims = valid.clone();
            claims[field] = value;
            assert!(verifier.verify(&signer.sign(&claims).unwrap()).is_err());
        }
        let mut mixed = valid.clone();
        for field in ["passkey_id", "ceremony_id", "magic_link_id"] {
            mixed[field] = id.clone();
        }
        assert!(verifier.verify(&signer.sign(&mixed).unwrap()).is_err());
        let other = SigningIdentity::hmac("issuer".into(), b"different").unwrap();
        assert!(verifier.verify(&other.sign(&valid).unwrap()).is_err());
    }

    #[test]
    fn challenges_bind_the_login_context_and_expire() {
        let signer = SigningIdentity::hmac("issuer".into(), b"test-secret").unwrap();
        let verifier = ChallengeVerifier::hmac("issuer", b"test-secret").unwrap();
        let now = Utc::now();
        let user = Uuid::new_v4();
        let ttl = TimeDelta::minutes(5);
        for binding in [
            Binding::Password,
            Binding::EmailLink(Uuid::new_v4()),
            Binding::Passkey {
                passkey: Uuid::new_v4(),
                ceremony: Uuid::new_v4(),
            },
        ] {
            let issue = |time| signer.issue_mfa(user, binding, time, ttl).unwrap();
            let result = verifier.verify(&issue(now)).unwrap();
            assert_eq!(
                (result.user, result.binding, result.expires.timestamp()),
                (user, binding, (now + ttl).timestamp())
            );
            assert_ne!(result.id, verifier.verify(&issue(now)).unwrap().id);
            assert!(verifier.verify(&issue(now - ttl - ttl)).is_err());
        }
        assert!(
            signer
                .issue_mfa(user, Binding::Password, now, TimeDelta::zero())
                .is_err()
        );
    }
}
