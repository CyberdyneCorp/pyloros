use std::{env, error::Error};

pub fn flag(name: &str) -> Result<bool, Box<dyn Error>> {
    match env::var(name).as_deref() {
        Err(env::VarError::NotPresent) | Ok("0" | "false") => Ok(false),
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
