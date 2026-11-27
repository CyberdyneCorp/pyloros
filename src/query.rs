//! Query integers accepted by the REST API.
pub(crate) fn integer(raw: &str) -> Result<String, (&'static str, &'static str)> {
    const INVALID: (&str, &str) = (
        "int_parsing",
        "Input should be a valid integer, unable to parse string as an integer",
    );
    let n = raw.trim();
    let whole = match n.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() && fraction.bytes().all(|b| b == b'0') => {
            whole
        }
        Some(_) => return Err(INVALID),
        None => n,
    };
    let digits = whole.strip_prefix(['-', '+']).unwrap_or(whole);
    if digits.is_empty()
        || !digits
            .split('_')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(INVALID);
    }
    let normalized = digits.replace('_', "");
    let significant = normalized.trim_start_matches('0');
    if significant.len() > 4300 {
        return Err((
            "int_parsing_size",
            "Unable to parse input string as an integer, exceeded maximum size",
        ));
    }
    Ok(whole.replace('_', ""))
}

pub(crate) fn active_only(value: Option<&str>) -> Result<bool, serde_json::Value> {
    match value.map(str::to_ascii_lowercase).as_deref() {
        None | Some("0" | "false" | "no" | "off" | "n" | "f") => Ok(false),
        Some("1" | "true" | "yes" | "on" | "y" | "t") => Ok(true),
        _ => Err(
            serde_json::json!({"type":"bool_parsing","loc":["query","active_only"],"msg":"Input should be a valid boolean, unable to interpret input","input":value}),
        ),
    }
}

fn uuid_reason(path: &str, error: uuid::Error) -> String {
    if path.bytes().all(|c| c.is_ascii_hexdigit()) {
        return format!(
            "invalid length: expected length 32 for simple format, found {}",
            path.len()
        );
    }
    let message = error.to_string();
    if message.starts_with("invalid character:")
        && let Some((prefix, offset)) = message.rsplit_once(" at ")
        && let Ok(index) = offset.parse::<usize>()
    {
        return format!("{prefix} at {}", index + 1);
    }
    message
}

pub(crate) fn path_uuid(path: &str, field: &str) -> Result<uuid::Uuid, serde_json::Value> {
    uuid::Uuid::parse_str(path).map_err(|error| {
        let reason = uuid_reason(path, error);
        serde_json::json!({
            "type":"uuid_parsing", "loc":["path",field],
            "msg":format!("Input should be a valid UUID, {reason}"),
            "input":path, "ctx":{"error":reason}
        })
    })
}
