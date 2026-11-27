//! Signing identity shared by session and MFA credentials.
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;

#[derive(Clone)]
pub struct SigningIdentity {
    issuer: String,
    header: Header,
    key: EncodingKey,
}

impl SigningIdentity {
    pub fn rsa(
        issuer: String,
        kid: String,
        pem: &[u8],
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid);
        Ok(Self {
            issuer,
            header,
            key: EncodingKey::from_rsa_pem(pem)?,
        })
    }

    pub fn hmac(issuer: String, secret: &[u8]) -> Result<Self, &'static str> {
        if secret.is_empty() {
            return Err("missing signing secret");
        }
        Ok(Self {
            issuer,
            header: Header::new(Algorithm::HS256),
            key: EncodingKey::from_secret(secret),
        })
    }

    pub(crate) fn supports_id_tokens(&self) -> bool {
        self.header.alg == Algorithm::RS256
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) fn sign(
        &self,
        claims: &impl Serialize,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        encode(&self.header, claims, &self.key)
    }
}
