//! Numeric tokens accepted by the operator role-session request decoder.
use super::{encoding, is_json, json_issue};
use crate::login_http::problem;
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{json, value::RawValue};
use std::borrow::Cow;

fn bad_body() -> Box<Response> {
    Box::new(problem(
        StatusCode::BAD_REQUEST,
        "There was an error parsing the body",
    ))
}

pub(crate) fn document(
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<Option<Box<RawValue>>, Box<Response>> {
    if bytes.is_empty() || !is_json(headers) {
        return super::fields::document(headers, bytes);
    }
    let text = encoding::text(bytes).map_err(|_| bad_body())?;
    let normalized = tokens(&text)?;
    serde_json::from_str(&normalized)
        .map(Some)
        .map_err(|error| {
            let mut issue = json_issue(normalized.as_bytes(), error);
            // Replacements keep their character count except NaN, which grows by two.
            if let Some(offset) = issue["loc"][1].as_u64()
                && matches!(normalized, Cow::Owned(_))
            {
                issue["loc"][1] = json!(original_offset(&text, &normalized, offset as usize));
            }
            Box::new(
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({"detail":[issue]})),
                )
                    .into_response(),
            )
        })
}

// Return complete non-string tokens without interpreting quoted escapes as delimiters.
fn spans(text: &str) -> impl Iterator<Item = (usize, &str)> {
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

fn tokens(text: &str) -> Result<Cow<'_, str>, Box<Response>> {
    let mut output = String::new();
    let mut cursor = 0;
    for (start, token) in spans(text) {
        let magnitude = token.strip_prefix('-').unwrap_or(token);
        if magnitude.len() > 4300
            && !magnitude.starts_with('0')
            && magnitude.bytes().all(|c| c.is_ascii_digit())
        {
            return Err(bad_body());
        }
        // All three literals are non-finite; validation errors containing them
        // take the same response path as a numeric exponent that overflows.
        let replacement = match token {
            "NaN" => "1e999",
            "Infinity" => "1e999999",
            "-Infinity" => "-1e999999",
            _ => continue,
        };
        output.push_str(&text[cursor..start]);
        output.push_str(replacement);
        cursor = start + token.len();
    }
    if cursor == 0 {
        return Ok(Cow::Borrowed(text));
    }
    output.push_str(&text[cursor..]);
    Ok(Cow::Owned(output))
}

fn original_offset(text: &str, normalized: &str, offset: usize) -> usize {
    let end = normalized
        .char_indices()
        .nth(offset)
        .map_or(normalized.len(), |(i, _)| i);
    let mut extra = 0;
    for (start, token) in spans(text) {
        if start + extra >= end {
            break;
        }
        if token == "NaN" {
            extra += 2;
        }
    }
    offset.saturating_sub(extra)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonfinite_literals_preserve_quoted_values_and_unicode_error_offsets() {
        let wire = r#"{"雪":"NaN\"", "x":[NaN,-Infinity,Infinity], "bad":}"#;
        let normalized = tokens(wire).unwrap();
        assert_eq!(
            normalized,
            r#"{"雪":"NaN\"", "x":[1e999,-1e999999,1e999999], "bad":}"#
        );
        assert_eq!(
            original_offset(wire, &normalized, normalized.chars().count() - 1),
            wire.chars().count() - 1
        );
    }

    #[test]
    fn decimal_digit_limit_applies_to_integer_tokens_only() {
        let digits = "9".repeat(4301);
        assert!(tokens(&digits).is_err());
        for input in [
            digits[..4300].to_owned(),
            format!("\u{22}{digits}\u{22}"),
            format!("{digits}.0"),
        ] {
            assert_eq!(tokens(&input).unwrap(), input);
        }
    }
}
