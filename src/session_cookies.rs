//! Cookie transport shared by browser login, rotation and logout handlers.
use axum::http::{HeaderMap, HeaderValue, header::SET_COOKIE};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use std::{env, error::Error};

pub(crate) const ACCESS: &str = "access_token";
const REFRESH: &str = "refresh_token";
const AUTH_PATH: &str = "/api/v1/auth";

pub(crate) fn csrf_name() -> Result<String, &'static str> {
    let name = env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrf".into());
    validate_name(&name)?;
    Ok(name)
}

fn validate_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty()
        || matches!(name, ACCESS | REFRESH)
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return Err("invalid or conflicting CSRF cookie name");
    }
    Ok(())
}

pub fn secure_transport(production: bool) -> Result<bool, Box<dyn Error>> {
    let configured = crate::config::flag("COOKIE_SECURE")?;
    let forced = crate::config::flag("FORCE_SECURE_COOKIES")?;
    Ok(production || configured || forced)
}

#[derive(Debug, thiserror::Error)]
pub enum CookieError {
    #[error("invalid session cookie value")]
    Value,
    #[error("could not generate a CSRF token")]
    Random,
}

pub struct SessionCookies {
    csrf: String,
    domain_attribute: String,
    secure: bool,
}

impl SessionCookies {
    pub fn configured(production: bool) -> Result<Self, Box<dyn Error>> {
        let domain = env::var("COOKIE_DOMAIN").ok();
        Ok(Self::new(
            csrf_name()?,
            domain.as_deref(),
            secure_transport(production)?,
        )?)
    }

    pub fn new(csrf: String, domain: Option<&str>, secure: bool) -> Result<Self, &'static str> {
        validate_name(&csrf)?;
        let domain_attribute = match domain {
            None | Some("") => String::new(),
            Some(value)
                if value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')) =>
            {
                format!("; Domain={value}")
            }
            _ => return Err("invalid COOKIE_DOMAIN"),
        };
        Ok(Self {
            csrf,
            domain_attribute,
            secure,
        })
    }

    /// Append the complete cookie set and return the CSRF value for this issuance.
    pub fn set(
        &self,
        headers: &mut HeaderMap,
        access: &str,
        refresh: &str,
        access_seconds: u64,
        refresh_seconds: u64,
    ) -> Result<String, CookieError> {
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| CookieError::Random)?;
        let csrf = URL_SAFE_NO_PAD.encode(nonce);
        let cookies = [
            self.cookie(ACCESS, access, access_seconds)?,
            self.cookie(REFRESH, refresh, refresh_seconds)?,
            self.cookie(&self.csrf, &csrf, access_seconds)?,
        ];
        for cookie in cookies {
            headers.append(SET_COOKIE, cookie);
        }
        Ok(csrf)
    }

    fn cookie(&self, name: &str, value: &str, age: u64) -> Result<HeaderValue, CookieError> {
        // The session credentials and CSRF nonce all use the URL-safe JWT alphabet.
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(CookieError::Value);
        }
        let http_only = if name == self.csrf { "" } else { "; HttpOnly" };
        let (path, site) = if name == REFRESH {
            (AUTH_PATH, "strict")
        } else {
            ("/", "lax")
        };
        let secure = if self.secure { "; Secure" } else { "" };
        let mut header = HeaderValue::from_str(&format!(
            "{name}={value}{}{http_only}; Max-Age={age}; Path={path}; SameSite={site}{secure}",
            self.domain_attribute
        ))
        .map_err(|_| CookieError::Value)?;
        header.set_sensitive(true);
        Ok(header)
    }

    pub fn clear(&self, headers: &mut HeaderMap, now: DateTime<Utc>) {
        let expires = now.format("%a, %d %b %Y %H:%M:%S GMT");
        for (name, path) in [(ACCESS, "/"), (REFRESH, AUTH_PATH), (&self.csrf, "/")] {
            let value = format!(
                "{name}=\"\"{}; expires={expires}; Max-Age=0; Path={path}; SameSite=lax",
                self.domain_attribute
            );
            headers.append(
                SET_COOKIE,
                HeaderValue::from_str(&value).expect("validated cookie name and domain"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_updates_three_cookies_and_replaces_the_csrf_secret() {
        let policy = SessionCookies::new("csrf".into(), None, true).unwrap();
        let mut previous = None;
        for _ in 0..2 {
            let mut headers = HeaderMap::new();
            let csrf = policy.set(&mut headers, "a.b.c", "r.s.t", 30, 60).unwrap();
            assert_eq!(URL_SAFE_NO_PAD.decode(&csrf).unwrap().len(), 32);
            assert_ne!(previous.as_ref(), Some(&csrf));
            let cookies: Vec<_> = headers
                .get_all(SET_COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect();
            assert_eq!(
                cookies,
                [
                    "access_token=a.b.c; HttpOnly; Max-Age=30; Path=/; SameSite=lax; Secure",
                    "refresh_token=r.s.t; HttpOnly; Max-Age=60; Path=/api/v1/auth; SameSite=strict; Secure",
                    &format!("csrf={csrf}; Max-Age=30; Path=/; SameSite=lax; Secure")
                ]
            );
            previous = Some(csrf);
        }
    }

    #[test]
    fn invalid_values_leave_existing_headers_intact() {
        let policy = SessionCookies::new("custom".into(), Some(".example.test"), false).unwrap();
        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, HeaderValue::from_static("other=value"));
        assert!(
            policy
                .set(&mut headers, "valid", "bad; Path=/", 10, 10)
                .is_err()
        );
        assert_eq!(headers.get_all(SET_COOKIE).iter().count(), 1);
        assert!(SessionCookies::new("refresh_token".into(), None, false).is_err());
        assert!(SessionCookies::new("custom".into(), Some("domain; Secure"), false).is_err());
    }
}
