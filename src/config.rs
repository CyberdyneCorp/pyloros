use std::{env, error::Error};

pub(crate) const PACKAGED_SCOPES: Option<&str> = option_env!("PYLOROS_BUILD_SCOPE_CATALOG");

pub fn flag(name: &str) -> Result<bool, Box<dyn Error>> {
    flag_with_default(name, false)
}

pub(crate) fn flag_with_default(name: &str, default: bool) -> Result<bool, Box<dyn Error>> {
    match env::var(name).as_deref() {
        Err(env::VarError::NotPresent) => Ok(default),
        Ok("0" | "false") => Ok(false),
        Ok("1" | "true") => Ok(true),
        _ => Err(format!("{name} must be true, false, 1, or 0").into()),
    }
}

pub(crate) fn insecure_webhook_http() -> Result<bool, Box<dyn Error>> {
    let enabled = flag("WEBHOOKS_ALLOW_INSECURE_HTTP")?;
    if enabled && env::var("APP_ENV").as_deref() == Ok("production") {
        return Err("insecure webhook HTTP is disabled in production".into());
    }
    Ok(enabled)
}

pub(crate) fn pem(path_var: &str, inline_var: &str) -> Result<Option<String>, Box<dyn Error>> {
    if let Some(path) = env::var(path_var).ok().filter(|s| !s.trim().is_empty()) {
        return Ok(Some(std::fs::read_to_string(path)?));
    }
    Ok(env::var(inline_var)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            if s.contains('\n') {
                s
            } else {
                s.replace("\\n", "\n")
            }
        }))
}

pub(crate) fn admin_emails() -> Result<Vec<String>, Box<dyn Error>> {
    string_list("ADMIN_EMAIL_LIST")
}

pub(crate) fn string_list(name: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let list = env::var(name).unwrap_or_default();
    let admins = if list.trim_start().starts_with('[') {
        serde_json::from_str(&list)?
    } else {
        list.split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .collect()
    };
    Ok(admins)
}

pub(crate) fn effective_admin(
    stored: bool,
    email: Option<&str>,
    verified: bool,
    require_verified: bool,
    allowed: &[String],
) -> bool {
    stored || ((!require_verified || verified) && bootstrap_admin(email, allowed))
}

pub(crate) fn bootstrap_admin(email: Option<&str>, allowed: &[String]) -> bool {
    email.is_some_and(|value| {
        let email = value.to_lowercase();
        !email.is_empty()
            && allowed
                .iter()
                .any(|entry| entry.trim().to_lowercase() == email)
    })
}

pub(crate) fn forwarded_peers() -> Vec<ipnet::IpNet> {
    let proxy_peers = std::env::var("FORWARDED_ALLOW_IPS").unwrap_or_else(|_| "127.0.0.1".into());
    proxy_peers
        .split(',')
        .map(str::trim)
        .flat_map(|p| {
            if p == "*" {
                return vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
            }
            p.parse()
                .ok()
                .or_else(|| p.parse::<std::net::IpAddr>().ok().map(Into::into))
                .into_iter()
                .collect()
        })
        .collect()
}

pub(crate) fn configured_issuer() -> Option<String> {
    std::env::var("OIDC_ISSUER")
        .ok()
        .filter(|issuer| !issuer.is_empty())
}

pub(crate) fn session_issuer() -> String {
    configured_issuer()
        .or_else(|| std::env::var("JWT_ISSUER").ok())
        .unwrap_or_else(|| "cyberdyne-auth".into())
}

pub(crate) enum SigningAlgorithm {
    Hs256,
    Rs256,
}

pub(crate) fn signing_algorithm() -> Result<SigningAlgorithm, Box<dyn Error>> {
    match env::var("JWT_ALGORITHM").as_deref() {
        Ok("HS256") | Err(env::VarError::NotPresent) => Ok(SigningAlgorithm::Hs256),
        Ok("RS256") => Ok(SigningAlgorithm::Rs256),
        _ => Err("unsupported JWT signing algorithm".into()),
    }
}

pub(crate) fn rsa_public_key(text: &str) -> Result<rsa::RsaPublicKey, Box<dyn Error>> {
    use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey};
    use x509_parser::prelude::{FromDer, X509Certificate};
    let block = pem::parse(text)?;
    let der = block.contents();
    match block.tag() {
        "PUBLIC KEY" => Ok(rsa::RsaPublicKey::from_public_key_der(der)?),
        "RSA PUBLIC KEY" => Ok(rsa::RsaPublicKey::from_pkcs1_der(der)?),
        "CERTIFICATE" => {
            let (_, cert) =
                X509Certificate::from_der(der).map_err(|_| "invalid signing certificate")?;
            Ok(rsa::RsaPublicKey::from_public_key_der(
                cert.public_key().raw,
            )?)
        }
        _ => Err("expected an RSA public key or signing certificate".into()),
    }
}
