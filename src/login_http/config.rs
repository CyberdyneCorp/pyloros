use super::*;
use crate::token_runtime::{lifetime, number};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
};

fn identity(production: bool) -> Result<Option<SigningIdentity>, Box<dyn Error>> {
    let public = crate::config::pem("JWT_PUBLIC_KEY_PATH", "JWT_PUBLIC_KEY")?;
    let algorithm = env::var("JWT_ALGORITHM")
        .unwrap_or_else(|_| if public.is_some() { "RS256" } else { "HS256" }.into());
    let issuer = env::var("OIDC_ISSUER")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_owned())
        .or_else(|| env::var("JWT_ISSUER").ok())
        .unwrap_or_else(|| "cyberdyne-auth".into());
    match algorithm.as_str() {
        "HS256" => {
            let Ok(secret) = env::var("JWT_SECRET_KEY") else {
                return Ok(None);
            };
            if production && secret.len() < 32 {
                return Err("invalid production JWT secret".into());
            }
            Ok(Some(SigningIdentity::hmac(issuer, secret.as_bytes())?))
        }
        "RS256" => {
            let Some(private) = crate::config::pem("JWT_PRIVATE_KEY_PATH", "JWT_PRIVATE_KEY")?
            else {
                return Ok(None);
            };
            let key = RsaPrivateKey::from_pkcs8_pem(&private)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&private))?
                .to_public_key();
            let public =
                RsaPublicKey::from_public_key_pem(&public.ok_or("missing JWT public key")?)?;
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
            Ok(Some(SigningIdentity::rsa(issuer, kid, private.as_bytes())?))
        }
        _ => Err("unsupported login signing algorithm".into()),
    }
}

impl Login {
    pub(super) fn configured(
        pool: PgPool,
        production: bool,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        let Some(signing) = identity(production)? else {
            return Ok(None);
        };
        let refresh = lifetime("JWT_REFRESH_TOKEN_TTL_DAYS", 30, 86400)?;
        Ok(Some(Self {
            pool,
            issuer: GrantSessionIssuer::with_identity(signing.clone(), refresh)?,
            signing,
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
            throttle: LoginThrottle::configured()?,
        }))
    }
}
