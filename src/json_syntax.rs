//! Validate bounded hook input while leaving numeric interpretation to the guest.
use serde_json::{Value, value::RawValue};

pub(crate) fn valid_hook_event(bytes: &[u8]) -> bool {
    if serde_json::from_slice::<Value>(bytes).is_ok() {
        return true;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    if serde_json::from_str::<&RawValue>(text).is_err() {
        return false;
    }
    // RawValue checked number grammar. Keep strings and structure intact so
    // the regular decoder still enforces Unicode and nesting restrictions.
    let mut normalized = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, token) in unquoted_tokens(text) {
        if matches!(token.as_bytes()[0], b'-' | b'0'..=b'9') {
            normalized.push_str(&text[cursor..start]);
            normalized.push('0');
            cursor = start + token.len();
        }
    }
    normalized.push_str(&text[cursor..]);
    serde_json::from_str::<Value>(&normalized).is_ok()
}

// Return complete non-string tokens without interpreting quoted escapes as delimiters.
pub(crate) fn unquoted_tokens(text: &str) -> impl Iterator<Item = (usize, &str)> {
    const SEPARATORS: &[char] = &['{', '}', ',', '[', ']', ':', ' ', '\n', '\r', '\t'];
    let mut rest = text;
    std::iter::from_fn(move || {
        loop {
            rest = rest.trim_start_matches(SEPARATORS);
            if rest.is_empty() {
                return None;
            }
            if rest.starts_with('"') {
                let mut string = serde_json::Deserializer::from_str(rest).into_iter::<&RawValue>();
                string.next()?.ok()?;
                rest = &rest[string.byte_offset()..];
                continue;
            }
            let end = rest
                .find(|c| c == '"' || SEPARATORS.contains(&c))
                .unwrap_or(rest.len());
            let start = text.len() - rest.len();
            let (token, next) = rest.split_at(end);
            rest = next;
            return Some((start, token));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::valid_hook_event as valid;

    #[test]
    fn accepts_large_numbers_and_preserves_string_and_structure_checks() {
        assert!(valid(
            br#"{"unknown":[1e999,-1e999],"event_type":"field \"1e999\""}"#
        ));
        assert!(valid(format!("{{\"n\":{}}}", "9".repeat(400)).as_bytes()));
        for bad in [
            br#"[1e999,"\ud800"]"#.as_slice(),
            b"[1e999,01]",
            b"[1e999,]",
            b"[1e999] true",
            b"[1e999,1e+]",
        ] {
            assert!(!valid(bad));
        }
        assert!(!valid(
            format!("{}1e999{}", "[".repeat(140), "]".repeat(140)).as_bytes()
        ));
    }
}
