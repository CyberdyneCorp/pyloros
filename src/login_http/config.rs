use super::*;
use crate::token_runtime::{lifetime, number};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{
    RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts,
};

pub(crate) fn identity(
    production: bool,
) -> Result<Option<(SigningIdentity, ChallengeVerifier)>, Box<dyn Error>> {
    use crate::config::SigningAlgorithm;
    let issuer = crate::config::session_issuer();
    match crate::config::signing_algorithm()? {
        SigningAlgorithm::Hs256 => {
            let Ok(secret) = env::var("JWT_SECRET_KEY") else {
                return Ok(None);
            };
            if production && secret.len() < 32 {
                return Err("invalid production JWT secret".into());
            }
            let verifier = ChallengeVerifier::hmac(&issuer, secret.as_bytes())?;
            Ok(Some((
                SigningIdentity::hmac(issuer, secret.as_bytes())?,
                verifier,
            )))
        }
        SigningAlgorithm::Rs256 => {
            let Some(private) = crate::config::pem("JWT_PRIVATE_KEY_PATH", "JWT_PRIVATE_KEY")?
            else {
                return Ok(None);
            };
            let key = RsaPrivateKey::from_pkcs8_pem(&private)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&private))?
                .to_public_key();
            let pem = crate::config::pem("JWT_PUBLIC_KEY_PATH", "JWT_PUBLIC_KEY")?
                .ok_or("missing JWT public key")?;
            let verifier = ChallengeVerifier::rsa(&issuer, pem.as_bytes())?;
            let public = crate::config::rsa_public_key(&pem)?;
            if public != key {
                return Err("JWT public and private keys do not match".into());
            }
            let kid = env::var("JWT_KEY_ID")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    crate::discovery::rsa_kid(
                        &URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
                        &URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
                    )
                });
            Ok(Some((
                SigningIdentity::rsa(issuer, kid, private.as_bytes())?,
                verifier,
            )))
        }
    }
}

impl Login {
    pub(crate) fn configured(
        pool: PgPool,
        production: bool,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        let Some((signing, verifier)) = identity(production)? else {
            return Ok(None);
        };
        let refresh = lifetime("JWT_REFRESH_TOKEN_TTL_DAYS", 30, 86400)?;
        let grace = number("REFRESH_REUSE_GRACE_SECONDS", 10)?;
        if !(0..=60).contains(&grace) {
            return Err("refresh reuse grace must be between 0 and 60 seconds".into());
        }
        let signed_out = match env::var_os("PYLOROS_SIGNED_OUT_HTML_PATH") {
            Some(path) => std::fs::read_to_string(path)?,
            None => {
                "<!doctype html><html lang=en><title>Signed out</title><p>Signed out</p></html>"
                    .into()
            }
        };
        Ok(Some(Self {
            oidc_issuer: crate::config::configured_issuer()
                .map(|s| s.trim_end_matches('/').to_owned()),
            signed_out,
            passkeys: passkey::Policy::configured()?,
            reuse_grace: TimeDelta::seconds(grace),
            pool,
            issuer: GrantSessionIssuer::with_identity(signing.clone(), refresh)?,
            signing,
            verifier,
            poll_quota: LoginThrottle::new(if number("RATELIMIT_LOGIN_PER_MIN", 10)? > 0 {
                120
            } else {
                0
            }),
            challenge: lifetime("MFA_CHALLENGE_TTL_MINUTES", 5, 60)?,
            access: lifetime("JWT_ACCESS_TOKEN_TTL_MINUTES", 15, 60)?,
            refresh,
            mail: ConfirmationMailer::configured()?,
            cookies: SessionCookies::configured(production)?,
            scheme: env::var("PASSWORD_SCHEME")
                .unwrap_or_else(|_| "argon2".into())
                .parse()?,
            admins: crate::config::admin_emails()?,
            production,
            proxies: number("TRUSTED_PROXY_COUNT", 0)?.try_into()?,
            hooks: env::var_os("HOOKS_ENABLED").is_none() || crate::config::flag("HOOKS_ENABLED")?,
            enforce_revocation: crate::config::flag("ENFORCE_TOKEN_REVOCATION")?,
            revoke_quota: LoginThrottle::new(60),
            cli_quota: LoginThrottle::configured()?,
            throttle: LoginThrottle::configured()?,
            mfa_quota: LoginThrottle::configured()?,
            factor: env::var("MASTER_KEY")
                .ok()
                .map(|key| FactorVerifier::new(&key))
                .transpose()?,
        }))
    }
}
