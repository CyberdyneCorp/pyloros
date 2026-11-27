use crate::mfa_challenges::ChallengeVerifier;
use crate::token_revocation::{TokenError, VerifiedToken};
use chrono::DateTime;
use jsonwebtoken::errors::ErrorKind;
use serde_json::Value;
use uuid::Uuid;

impl ChallengeVerifier {
    /// Check a credential at its issuer. The audience identifies a relying party or resource.
    pub fn token_for_revocation(&self, token: &str) -> Result<VerifiedToken, TokenError> {
        self.token_for_revocation_at(token, None)
    }

    pub(crate) fn token_for_revocation_at(
        &self,
        token: &str,
        oidc_issuer: Option<&str>,
    ) -> Result<VerifiedToken, TokenError> {
        let claims = match self.verified_claims(token) {
            Ok(claims)
                if claims["type"].is_null()
                    && oidc_issuer.is_some_and(|issuer| claims["iss"] != issuer) =>
            {
                return Err(TokenError::Invalid);
            }
            Ok(claims) => claims,
            Err(_) if self.logout_client_hint(token, oidc_issuer).is_some() => {
                return Err(TokenError::Unsupported);
            }
            Err(error) if matches!(error.kind(), ErrorKind::ExpiredSignature) => {
                return Err(TokenError::Expired);
            }
            Err(_) => return Err(TokenError::Invalid),
        };
        VerifiedToken::from_verified_claims(&claims)
    }
}

fn uuid(claims: &Value, name: &str) -> Result<Uuid, TokenError> {
    claims[name]
        .as_str()
        .and_then(|id| id.parse().ok())
        .ok_or(TokenError::Invalid)
}

impl VerifiedToken {
    pub(crate) fn from_verified_claims(claims: &Value) -> Result<Self, TokenError> {
        let kind = claims["type"].as_str();
        let client = claims["client_id"].as_str();
        match kind {
            None if claims["type"].is_null()
                && claims["aud"].as_str().is_some_and(|s| !s.is_empty()) =>
            {
                uuid(claims, "sub")?;
                Err(TokenError::Unsupported)
            }
            Some("mfa") => {
                uuid(claims, "sub")?;
                Err(TokenError::Unsupported)
            }
            Some("consent") => {
                uuid(claims, "sub")?;
                if ["client_id", "resource", "scope", "authz"]
                    .iter()
                    .all(|field| claims.get(field).is_some())
                {
                    Err(TokenError::Unsupported)
                } else {
                    Err(TokenError::Invalid)
                }
            }
            Some("refresh") => Ok(VerifiedToken::Refresh {
                id: uuid(claims, "jti")?,
                session: uuid(claims, "sid")?,
                user: uuid(claims, "sub")?,
            }),
            Some("access" | "service") => {
                let id = uuid(claims, "jti")?;
                let expires = claims["exp"]
                    .as_i64()
                    .and_then(|t| DateTime::from_timestamp(t, 0))
                    .ok_or(TokenError::Invalid)?;
                if kind == Some("access") {
                    if !claims["sid"].is_null() {
                        uuid(claims, "sid")?;
                    }
                    Ok(VerifiedToken::Access {
                        id,
                        expires,
                        user: uuid(claims, "sub")?,
                        client: client.map(str::to_owned),
                    })
                } else {
                    let client = client
                        .filter(|s| !s.is_empty())
                        .ok_or(TokenError::Invalid)?;
                    claims["iat"].as_i64().ok_or(TokenError::Invalid)?;
                    Ok(VerifiedToken::Service {
                        id,
                        expires,
                        client: client.to_owned(),
                    })
                }
            }
            _ => Err(TokenError::Invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::SigningIdentity;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn distinguishes_issuer_signed_credentials_and_expired_id_tokens() {
        let verifier = ChallengeVerifier::hmac("issuer", b"fixture").unwrap();
        let signer = SigningIdentity::hmac("issuer".into(), b"fixture").unwrap();
        let user = Uuid::new_v4();
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        let timestamp = Utc::now().timestamp();
        let mut claims = json!({"iss":"issuer","sub":user,"jti":id,"sid":session,"iat":timestamp,"exp":timestamp+300,"aud":"resource","client_id":"app"});
        let read = |claims: &Value| verifier.token_for_revocation(&signer.sign(claims).unwrap());
        claims["type"] = json!("access");
        assert!(
            matches!(read(&claims),Ok(VerifiedToken::Access{id:j,user:u,client:Some(c),..}) if j==id && u==user && c=="app")
        );
        claims["type"] = json!("refresh");
        assert!(matches!(read(&claims),Ok(VerifiedToken::Refresh{session:s,..}) if s==session));
        claims["type"] = json!("service");
        claims["sub"] = json!("app");
        assert!(matches!(read(&claims),Ok(VerifiedToken::Service{client,..}) if client=="app"));
        claims["exp"] = json!(1);
        assert!(matches!(read(&claims), Err(TokenError::Expired)));
        claims["sub"] = json!(user);
        claims.as_object_mut().unwrap().remove("type");
        assert!(matches!(read(&claims), Err(TokenError::Unsupported)));
        claims["iss"] = json!("other");
        claims["exp"] = json!(timestamp + 300);
        assert!(matches!(read(&claims), Err(TokenError::Invalid)));
        claims["iss"] = json!("issuer");
        claims["type"] = json!("mfa");
        assert!(matches!(read(&claims), Err(TokenError::Unsupported)));
        claims["type"] = json!("consent");
        assert!(matches!(read(&claims), Err(TokenError::Invalid)));
        for field in ["resource", "scope", "authz"] {
            claims[field] = json!("fixture");
        }
        assert!(matches!(read(&claims), Err(TokenError::Unsupported)));
        claims["type"] = json!("access");
        let mut missing_issuer = claims.clone();
        missing_issuer.as_object_mut().unwrap().remove("iss");
        assert!(matches!(read(&missing_issuer), Err(TokenError::Invalid)));
        let other = SigningIdentity::hmac("issuer".into(), b"another-key").unwrap();
        assert!(matches!(
            verifier.token_for_revocation(&other.sign(&claims).unwrap()),
            Err(TokenError::Invalid)
        ));
    }
}
