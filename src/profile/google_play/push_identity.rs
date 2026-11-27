//! Verify the identity attached to an authenticated Pub/Sub push delivery.
use super::*;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const KEYS: &str = "https://www.googleapis.com/oauth2/v3/certs";

pub(super) struct Identity {
    audience: String,
    email: String,
    cache: Mutex<Option<(Instant, JwkSet)>>,
}

#[derive(Deserialize)]
struct Sender {
    email_verified: bool,
    email: String,
    iat: i64,
}

impl Identity {
    pub(super) fn configured() -> Option<Self> {
        let setting = |name| env::var(name).ok().filter(|s| !s.trim().is_empty());
        Some(Self {
            audience: setting("GOOGLE_PUBSUB_AUDIENCE")?,
            email: setting("GOOGLE_PUBSUB_SERVICE_ACCOUNT_EMAIL")?,
            cache: Mutex::new(None),
        })
    }

    pub(super) async fn verify(&self, token: &str, http: &reqwest::Client) -> Result<(), Failure> {
        let header = decode_header(token).map_err(|_| Failure::Invalid)?;
        if header.alg != Algorithm::RS256 {
            return Err(Failure::Invalid);
        }
        let kid = header.kid.ok_or(Failure::Invalid)?;
        let mut cache = self.cache.lock().await;
        if cache
            .as_ref()
            .is_none_or(|(expiry, _)| Instant::now() >= *expiry)
        {
            let response = http
                .get(KEYS)
                .send()
                .await
                .map_err(|_| Failure::Unavailable)?
                .error_for_status()
                .map_err(|_| Failure::Unavailable)?;
            let ttl = response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| {
                    v.split(',')
                        .find_map(|part| part.trim().strip_prefix("max-age=")?.parse::<u64>().ok())
                })
                .unwrap_or(60)
                .min(3600);
            let bytes = response.bytes().await.map_err(|_| Failure::Unavailable)?;
            let keys = serde_json::from_slice(&bytes).map_err(|_| Failure::Unavailable)?;
            *cache = Some((Instant::now() + Duration::from_secs(ttl), keys));
        }
        let key = cache
            .as_ref()
            .and_then(|(_, keys)| keys.find(&kid))
            .ok_or(Failure::Invalid)?;
        let key = DecodingKey::from_jwk(key).map_err(|_| Failure::Invalid)?;
        drop(cache);
        self.verify_claims(token, &key)
    }

    fn verify_claims(&self, token: &str, key: &DecodingKey) -> Result<(), Failure> {
        let mut check = Validation::new(Algorithm::RS256);
        check.set_audience(&[&self.audience]);
        check.set_issuer(&["accounts.google.com", "https://accounts.google.com"]);
        check.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        check.validate_nbf = true;
        let sender = decode::<Sender>(token, key, &check)
            .map_err(|_| Failure::Invalid)?
            .claims;
        if sender.email_verified
            && sender.email == self.email
            && sender.iat <= Utc::now().timestamp() + 60
        {
            return Ok(());
        }
        Err(Failure::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

    #[test]
    fn validates_the_signed_sender_and_recipient() {
        let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let public = private
            .to_public_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let key = DecodingKey::from_rsa_pem(public.as_bytes()).unwrap();
        let pem = private.to_pkcs8_pem(Default::default()).unwrap();
        let signing = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let identity = Identity {
            email: "push@example.test".into(),
            audience: "billing".into(),
            cache: Mutex::new(None),
        };
        let now = Utc::now().timestamp();
        let claims = json!({"email":identity.email,"aud":identity.audience,"iss":"https://accounts.google.com","sub":"123","iat":now,"exp":now+3600,"email_verified":true});
        let sign =
            |claims: &Value| encode(&Header::new(Algorithm::RS256), claims, &signing).unwrap();
        assert!(identity.verify_claims(&sign(&claims), &key).is_ok());
        for (field, value) in [
            ("email", json!("another@example.test")),
            ("aud", json!("other")),
            ("email_verified", json!(false)),
            ("iat", json!(now + 3600)),
            ("exp", json!(now - 3600)),
            ("iss", json!("https://example.test")),
        ] {
            let mut changed = claims.clone();
            changed[field] = value;
            assert!(
                identity.verify_claims(&sign(&changed), &key).is_err(),
                "{field}"
            );
        }
    }
}
