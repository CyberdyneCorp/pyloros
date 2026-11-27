//! Account mailbox validation and the SMTP representation for long local parts.
use super::email_domain;
use lettre::{Address, message::Mailbox};
use std::collections::BTreeSet;
use unicode_general_category::{GeneralCategory::*, get_general_category};
use unicode_normalization::UnicodeNormalization;

fn ascii_atom(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c)
}

fn unsafe_character(index: usize, c: char) -> bool {
    match get_general_category(c) {
        Format | Control | PrivateUse | Unassigned | SpaceSeparator | LineSeparator
        | ParagraphSeparator => true,
        NonspacingMark | SpacingMark | EnclosingMark => index == 0,
        _ => false,
    }
}

fn label(c: char) -> String {
    if !c.is_ascii() && unsafe_character(0, c) {
        return unicode_names2::name(c).map_or_else(
            || format!("U+{:04X}", u32::from(c)),
            |name| name.to_string(),
        );
    }
    email_domain::character_label(c)
}

fn labels(chars: impl Iterator<Item = char>) -> String {
    chars
        .map(label)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ")
}

fn addr_spec(raw: &str) -> Result<&str, String> {
    let raw = raw.trim();
    let Some((name, inner)) = raw.strip_suffix('>').and_then(|s| s.split_once('<')) else {
        return Ok(raw);
    };
    let name = name.trim();
    if !name.starts_with('"') {
        let bad = labels(
            name.chars()
                .filter(|&c| !(c.is_alphanumeric() || ascii_atom(c) || c == ' ')),
        );
        if !bad.is_empty() {
            return Err(format!(
                "The display name contains invalid characters when not quoted: {bad}."
            ));
        }
    }
    // Validate the display syntax separately from the length of the actual address.
    if !name.is_empty() {
        format!("{name} <mail@example.com>")
            .parse::<Mailbox>()
            .map_err(|_| "The email address is not valid.")?;
    }
    Ok(inner.trim())
}

fn local_part(local: &str) -> Result<(), String> {
    let bad = labels(
        local
            .chars()
            .filter(|&c| c.is_ascii() && c != '.' && !ascii_atom(c)),
    );
    if !bad.is_empty() {
        return Err(format!(
            "The email address contains invalid characters before the @-sign: {bad}."
        ));
    }
    let unsafe_chars = labels(
        local
            .chars()
            .enumerate()
            .filter(|&(i, c)| unsafe_character(i, c))
            .map(|(_, c)| c),
    );
    if !unsafe_chars.is_empty() {
        return Err(format!(
            "The email address contains unsafe characters: {unsafe_chars}."
        ));
    }
    if local.starts_with('.') {
        return Err("An email address cannot start with a period.".into());
    }
    if local.ends_with('.') {
        return Err("An email address cannot have a period immediately before the @-sign.".into());
    }
    if local.contains("..") {
        return Err("An email address cannot have two periods in a row.".into());
    }
    Ok(())
}

fn size(input: &str, canonical: &str, local: &str, domain: &str) -> Result<(), String> {
    const MAX: usize = 254;
    if input.len() > MAX {
        let excess = input.len() - MAX;
        let width = input.chars().map(char::len_utf8).max().unwrap_or(1);
        let min = excess.div_ceil(width);
        let amount = if excess == min {
            excess.to_string()
        } else {
            format!("{min}-{excess}")
        };
        let plural = if excess == 1 { "" } else { "s" };
        return Err(format!(
            "The email address is too long ({amount} character{plural} too many)."
        ));
    }
    let ascii = idna::domain_to_ascii(domain).map_err(|_| "The email address is not valid.")?;
    for (length, stage) in [
        (canonical.len(), "after normalization"),
        (
            local.len() + 1 + ascii.len(),
            "when the part after the @-sign is converted to IDNA ASCII",
        ),
    ] {
        if length > MAX {
            let excess = length - MAX;
            let plural = if excess == 1 { "" } else { "s" };
            return Err(format!(
                "The email address is too long {stage} ({excess} byte{plural} too many)."
            ));
        }
    }
    Ok(())
}

pub(super) fn address(raw: &str) -> Result<String, String> {
    let input = addr_spec(raw)?;
    if let Some(quoted) = input.strip_prefix('"') {
        let (content, _) = quoted
            .rsplit_once("\"@")
            .ok_or("An email address must have an @-sign.")?;
        if content.is_empty() {
            return Err("There must be something before the @-sign.".into());
        }
        return Err("Quoting the part before the @-sign is not allowed here.".into());
    }
    let (local, domain) = input
        .split_once('@')
        .ok_or_else(|| email_domain::missing_separator(input))?;
    if local.is_empty() {
        return Err("There must be something before the @-sign.".into());
    }
    if domain.is_empty() {
        return Err("There must be something after the @-sign.".into());
    }
    local_part(local)?;
    email_domain::characters(domain)?;
    email_domain::check_dots_and_hyphens(domain)?;
    let domain = email_domain::validate(domain)?;
    Address::new("account", &domain).map_err(|_| "The email address is not valid.")?;
    let local: String = local.nfc().collect();
    let canonical = format!("{local}@{domain}");
    size(input, &canonical, &local, &domain)?;
    Ok(canonical)
}

pub(crate) fn recipient(raw: &str) -> Option<Mailbox> {
    if let Ok(mailbox) = raw.parse() {
        return Some(mailbox);
    }
    let (local, domain) = raw.split_once('@')?;
    if local.len() <= 64 || address(raw).ok()?.as_str() != raw {
        return None;
    }
    // The account rules above validate a bare dot-atom, domain and total length.
    // Lettre's normal constructor additionally caps the local part at 64 bytes.
    Some(Mailbox::new(None, Address::new_dangerous(local, domain)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_recipients_retain_the_same_envelope_and_address_limits() {
        let local = "a".repeat(65);
        let plain = format!("{local}@example.com");
        assert_eq!(address(&format!("User < {plain} >")).unwrap(), plain);
        assert_eq!(recipient(&plain).unwrap().email.to_string(), plain);
        assert!(recipient(&format!("{local},other@example.com")).is_none());
        assert!(recipient(&format!("{local}\r\nBcc: x@example.com")).is_none());
        assert!(recipient(&format!("{local}@invalid_domain.test")).is_none());
        assert!(address(&format!("{}@example.com", "a".repeat(242))).is_ok());
        assert!(recipient(&format!("{}@example.com", "a".repeat(243))).is_none());
    }

    #[test]
    fn local_diagnostics_preserve_unicode_names_and_byte_limits() {
        assert_eq!(
            address("a\u{200b}@example.org").unwrap_err(),
            "The email address contains unsafe characters: ZERO WIDTH SPACE."
        );
        assert_eq!(
            address("\"a@b\"@example.org").unwrap_err(),
            "Quoting the part before the @-sign is not allowed here."
        );
        assert_eq!(
            address(&format!("{}@example.com", "ü".repeat(122))).unwrap_err(),
            "The email address is too long (1-2 characters too many)."
        );
    }
}
