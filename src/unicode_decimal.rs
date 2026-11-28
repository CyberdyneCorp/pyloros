use unicode_general_category::{GeneralCategory::DecimalNumber, get_general_category};

// Unicode decimal digits are arranged in consecutive groups of ten.
pub(crate) fn decimal(c: char) -> Option<i64> {
    if c.is_ascii_digit() {
        return Some(i64::from(c as u8 - b'0'));
    }
    if get_general_category(c) != DecimalNumber {
        return None;
    }
    let point = u32::from(c);
    let mut start = point;
    while char::from_u32(start - 1).is_some_and(|p| get_general_category(p) == DecimalNumber) {
        start -= 1;
    }
    Some(i64::from((point - start) % 10))
}

pub(crate) fn hexadecimal_magnitude(raw: &str) -> Option<String> {
    let normalized: String = raw
        .trim()
        .chars()
        .map(|c| decimal(c).map_or(c, |digit| char::from(b'0' + digit as u8)))
        .collect();
    let number = normalized.strip_prefix(['+', '-']).unwrap_or(&normalized);
    let digits = match number
        .strip_prefix("0x")
        .or_else(|| number.strip_prefix("0X"))
    {
        Some(rest) => rest.strip_prefix('_').unwrap_or(rest),
        None => number,
    };
    digits
        .split('_')
        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| digits.replace('_', ""))
}
