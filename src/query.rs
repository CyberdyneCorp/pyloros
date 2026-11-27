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
