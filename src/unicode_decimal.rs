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
