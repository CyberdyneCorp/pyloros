//! Numeric conversions when loading historical PostgreSQL JSONB documents.
use crate::request_json::iam_document::unquoted_tokens;

fn invalid() -> sqlx::Error {
    sqlx::Error::Decode("stored JSON number is out of range".into())
}

pub(crate) fn check_integers(raw: &str) -> Result<(), sqlx::Error> {
    for (_, token) in unquoted_tokens(raw) {
        let digits = token.trim_start_matches('-');
        if digits.len() > 4300 && digits.bytes().all(|b| b.is_ascii_digit()) {
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
