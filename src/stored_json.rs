//! Numeric conversions when loading historical PostgreSQL JSONB documents.
use crate::request_json::iam_document::unquoted_tokens;

fn invalid() -> sqlx::Error {
    sqlx::Error::Decode("stored JSON number is out of range".into())
}

pub(crate) fn check_integers(raw: &str) -> Result<(), sqlx::Error> {
    const MAX_DIGITS: usize = 4300;
    if raw.len() <= MAX_DIGITS {
        return Ok(());
    }
    for (_, token) in unquoted_tokens(raw) {
        let digits = token.trim_start_matches('-');
        if digits.len() > MAX_DIGITS && digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(crate) fn project_fractions(json: String, for_database: bool) -> Result<String, sqlx::Error> {
    let mut normalized = String::new();
    let mut cursor = 0;
    for (start, token) in unquoted_tokens(&json) {
        if token.contains(['.', 'e', 'E'])
            && token.starts_with(|c: char| c.is_ascii_digit() || c == '-')
        {
            let value = token.parse::<f64>().map_err(|_| invalid())?;
            if for_database && !value.is_finite() {
                return Err(invalid());
            }
            normalized.push_str(&json[cursor..start]);
            normalized.push_str(&serde_json::to_string(&value).map_err(|_| invalid())?);
            cursor = start + token.len();
        }
    }
    if cursor == 0 {
        return Ok(json);
    }
    normalized.push_str(&json[cursor..]);
    Ok(normalized)
}

pub(crate) fn validate_client_set(raw: &str) -> sqlx::Result<()> {
    check_integers(raw)?;
    use serde_json::value::RawValue;
    let valid = match raw.as_bytes().first() {
        Some(b'n' | b'{' | b'"') => true,
        Some(b'[') => serde_json::from_str::<Vec<&RawValue>>(raw)
            .map_err(|e| sqlx::Error::Decode(e.into()))?
            .iter()
            .all(|v| !v.get().starts_with(['[', '{'])),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(sqlx::Error::Decode("invalid client collection".into()))
    }
}
