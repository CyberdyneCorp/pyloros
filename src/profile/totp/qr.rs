//! Encode an enrollment URI as a standard QR symbol with a transparent quiet zone.
use percent_encoding::utf8_percent_encode;
use qrcode::{Color, EcLevel, QrCode, Version, bits::Bits, types::QrError};
use std::fmt::Write;

fn symbol(uri: &str) -> Result<QrCode, QrError> {
    for version in 1..=40 {
        let mut bits = Bits::new(Version::Normal(version));
        let count_bits = if version <= 9 { 8 } else { 16 };
        let capacity = bits.max_len(EcLevel::M)?;
        if uri.len() > (capacity - 4 - count_bits) / 8 {
            continue;
        }
        bits.push_byte_data(uri.as_bytes())?;
        let mut level = EcLevel::M;
        for candidate in [EcLevel::H, EcLevel::Q] {
            if bits.len() <= bits.max_len(candidate)? {
                level = candidate;
                break;
            }
        }
        bits.push_terminator(level)?;
        return QrCode::with_bits(bits, level);
    }
    Err(QrError::DataTooLong)
}

pub(super) fn data_uri(uri: &str) -> Result<String, QrError> {
    let code = symbol(uri)?;
    let width = code.width();
    let extent = width + 8;
    let pixels = extent * 5;
    let mut svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{pixels}" height="{pixels}" viewBox="0 0 {extent} {extent}"><path stroke="black" d=""#
    );
    for y in 0..width {
        let mut x = 0;
        while x < width {
            let start = x;
            while x < width && code[(x, y)] == Color::Dark {
                x += 1;
            }
            if start < x {
                write!(svg, "M{} {}.5h{}", start + 4, y + 4, x - start).unwrap();
            }
            x += 1;
        }
    }
    svg.push_str(r#""/></svg>"#);
    Ok(format!(
        "data:image/svg+xml;charset=utf-8,{}",
        utf8_percent_encode(&svg, super::QUERY)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use percent_encoding::percent_decode_str;

    #[test]
    fn enrollment_data_uri_scales_the_symbol_and_its_quiet_zone_together() {
        let text =
            "otpauth://totp/demo:fixture?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&issuer=demo";
        let uri = data_uri(text).unwrap();
        let encoded = uri
            .strip_prefix("data:image/svg+xml;charset=utf-8,")
            .unwrap();
        let svg = percent_decode_str(encoded).decode_utf8().unwrap();
        assert!(svg.contains(r#"width="225" height="225" viewBox="0 0 45 45""#));
        assert!(svg.contains("M4 4.5h7"));
        assert_eq!(symbol(&"x".repeat(2400)).err(), Some(QrError::DataTooLong));
    }
}
