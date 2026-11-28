pub(super) fn format_float(value: f64) -> String {
    if !value.is_finite() {
        return value.to_string();
    }
    let mut buffer = ryu::Buffer::new();
    let decimal = buffer.format_finite(value);
    if let Some((mantissa, exponent)) = decimal.split_once('e') {
        let exponent: i32 = exponent.parse().expect("Ryū emits a decimal exponent");
        return format!("{mantissa}e{exponent:+03}");
    }
    // Ryū uses fixed notation for exponent -5. The source runtime uses scientific notation.
    let unsigned = decimal.trim_start_matches('-');
    if let Some(digits) = unsigned.strip_prefix("0.0000") {
        let sign = if value.is_sign_negative() { "-" } else { "" };
        let (head, tail) = digits.split_at(1);
        let point = if tail.is_empty() { "" } else { "." };
        return format!("{sign}{head}{point}{tail}e-05");
    }
    decimal.to_owned()
}
