//! Quoted cookie values can occur when an existing client supplies its own binding.
use axum::http::{HeaderMap, header};

pub(super) fn read(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|s| s.split(';'))
        .filter_map(|s| s.split_once('='))
        .filter(|(key, _)| key.trim() == "passkey_binding")
        .map(|(_, value)| value.trim())
        .next_back()?;
    let Some(quoted) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return Some(raw.to_owned());
    };
    let mut text = String::new();
    let mut chars = quoted.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            text.push(ch);
            continue;
        }
        let next = chars.as_str().as_bytes();
        if let [a @ b'0'..=b'3', b @ b'0'..=b'7', c @ b'0'..=b'7', ..] = next {
            text.push(char::from((a - b'0') * 64 + (b - b'0') * 8 + (c - b'0')));
            chars.nth(2);
        } else {
            text.push(chars.next().unwrap_or('\\'));
        }
    }
    Some(text)
}

pub(super) fn encode(secret: &str) -> String {
    if secret
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:".contains(&b))
    {
        return secret.to_owned();
    }
    let mut encoded = String::from("\"");
    for c in secret.chars() {
        match c {
            '\\' | '"' => {
                encoded.push('\\');
                encoded.push(c);
            }
            ',' | ';' | '\0'..='\x1f' | '\x7f'..='\u{ff}' => {
                encoded.push_str(&format!("\\{:03o}", u32::from(c)))
            }
            c => encoded.push(c),
        }
    }
    encoded.push('"');
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoted_cookie_round_trip() {
        for binding in [
            "base64url-123_A",
            "a=b",
            "semi;comma,quote\"",
            "back\\slash",
            "å",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::COOKIE,
                format!("passkey_binding={}", encode(binding))
                    .parse()
                    .unwrap(),
            );
            assert_eq!(read(&headers).as_deref(), Some(binding));
        }
    }
}
