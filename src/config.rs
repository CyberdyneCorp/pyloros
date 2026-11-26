use std::{env, error::Error};

pub fn flag(name: &str) -> Result<bool, Box<dyn Error>> {
    match env::var(name).as_deref() {
        Err(env::VarError::NotPresent) | Ok("0" | "false") => Ok(false),
        Ok("1" | "true") => Ok(true),
        _ => Err(format!("{name} must be true, false, 1, or 0").into()),
    }
}
