use std::{env, error::Error};

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
    let list = env::var("ADMIN_EMAIL_LIST").unwrap_or_default();
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
    stored
        || ((!require_verified || verified)
            && email.is_some_and(|value| {
                let email = value.to_lowercase();
                !email.is_empty()
                    && allowed
                        .iter()
                        .any(|entry| entry.trim().to_lowercase() == email)
            }))
}
