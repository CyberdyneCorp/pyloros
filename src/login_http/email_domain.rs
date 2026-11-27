//! Validate the DNS part of an account email address before transport parsing.
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
};

pub(super) fn missing_separator(input: &str) -> &'static str {
    if input.contains('＠') {
        return "The email address has the \"full-width\" at-sign (@) character instead of a regular at-sign.";
    }
    if input.contains('﹫') {
        return "The email address has the \"small commercial at\" character instead of a regular at-sign.";
    }
    "An email address must have an @-sign."
}

pub(super) fn character_label(c: char) -> String {
    match c {
        ' ' => "SPACE".into(),
        '\'' | '\\' => format!("\"{c}\""),
        c if c.is_ascii_control() => format!("U+{:04X}", u32::from(c)),
        _ => format!("'{c}'"),
    }
}

fn ip_literal(input: &str) -> bool {
    let Some(literal) = input.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return false;
    };
    literal.parse::<Ipv4Addr>().is_ok()
        || literal.split_once(':').is_some_and(|(tag, ip)| {
            tag.eq_ignore_ascii_case("IPv6") && ip.parse::<Ipv6Addr>().is_ok()
        })
}

pub(super) fn characters(input: &str) -> Result<(), String> {
    if ip_literal(input) {
        return Err("A bracketed IP address after the @-sign is not allowed here.".into());
    }
    let invalid: BTreeSet<_> = input
        .chars()
        .filter(|c| c.is_ascii() && !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.')))
        .map(character_label)
        .collect();
    if invalid.is_empty() {
        return Ok(());
    }
    let labels = invalid.into_iter().collect::<Vec<_>>().join(", ");
    Err(format!(
        "The part after the @-sign contains invalid characters: {labels}."
    ))
}

pub(super) fn check_dots_and_hyphens(domain: &str) -> Result<(), &'static str> {
    if domain.ends_with('.') {
        return Err("An email address cannot end with a period.");
    }
    if domain.starts_with('.') {
        return Err("An email address cannot have a period immediately after the @-sign.");
    }
    if domain.starts_with('-') {
        return Err("An email address cannot have a hyphen immediately after the @-sign.");
    }
    if domain.ends_with('-') {
        return Err("An email address cannot end with a hyphen.");
    }
    if domain.contains("-.") || domain.contains(".-") {
        return Err("An email address cannot have a period and a hyphen next to each other.");
    }
    if domain.contains("..") {
        return Err("An email address cannot have two periods in a row.");
    }
    Ok(())
}

fn excess(count: usize, unit: &str) -> String {
    let plural = if count == 1 { "" } else { "s" };
    format!("{count} {unit}{plural} too many")
}

fn dns_size(input: &str, ascii: &str) -> Result<(), String> {
    if ascii.len() > 253 {
        let count = ascii.len() - 253;
        let amount = if ascii == input {
            excess(count, "character")
        } else {
            format!("{} after IDNA encoding", excess(count, "byte"))
        };
        return Err(format!(
            "The email address is too long after the @-sign ({amount})."
        ));
    }
    if let Some(label) = ascii.split('.').find(|s| s.len() > 63) {
        if label.starts_with("xn--") {
            return Err("The part after the @-sign is invalid (Label too long).".into());
        }
        let amount = excess(label.len() - 63, "character");
        return Err(format!(
            "After the @-sign, periods cannot be separated by so many characters ({amount})."
        ));
    }
    Ok(())
}

pub(super) fn validate(input: &str) -> Result<String, String> {
    let invalid = "The email address is not valid.";
    let ascii = idna::domain_to_ascii(input).map_err(|_| invalid)?;
    dns_size(input, &ascii)?;
    let (_, suffix) = ascii
        .rsplit_once('.')
        .ok_or("The part after the @-sign is not valid. It should have a period.")?;
    if matches!(
        suffix,
        "arpa" | "test" | "invalid" | "localhost" | "local" | "onion"
    ) {
        return Err("The part after the @-sign is a special-use or reserved name that cannot be used with email.".into());
    }
    if suffix.ends_with(|c: char| c.is_ascii_digit()) && !suffix.starts_with("xn--") {
        return Err(
            "The part after the @-sign is not valid. It is not within a valid top-level domain."
                .into(),
        );
    }
    let (domain, validity) = idna::domain_to_unicode(&ascii);
    validity.map_err(|_| invalid)?;
    Ok(domain)
}
