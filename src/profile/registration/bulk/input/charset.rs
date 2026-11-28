//! Decode multipart text fields while retaining the original bytes on codec failure.
use encoding_rs::{Encoding, UTF_8, WINDOWS_1252};

fn latin1(bytes: Vec<u8>) -> String {
    bytes.into_iter().map(char::from).collect()
}

pub(super) fn decode(bytes: Vec<u8>, label: &str) -> String {
    let label = label.to_ascii_lowercase().replace('_', "-");
    if label == "utf-8-sig" {
        return std::str::from_utf8(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes))
            .map(str::to_owned)
            .unwrap_or_else(|_| latin1(bytes));
    }
    if let Some(width) = match label.as_str() {
        "utf-16" | "utf16" => Some(2),
        "utf-32" | "utf32" | "utf-32-le" | "utf-32-be" | "utf-32le" | "utf-32be" => Some(4),
        _ => None,
    } {
        return wide(&bytes, width, &label).unwrap_or_else(|| latin1(bytes));
    }
    let label = match label.as_str() {
        "utf-16-le" => "utf-16le",
        "utf-16-be" => "utf-16be",
        other => other,
    };
    let codec = Encoding::for_label(label.as_bytes());
    if codec == Some(UTF_8) {
        return String::from_utf8(bytes).unwrap_or_else(|err| latin1(err.into_bytes()));
    }
    // The web encoding registry aliases ASCII and Latin-1 to Windows-1252.
    // Multipart fields retain the submitted code points for those labels.
    if codec == Some(WINDOWS_1252) && !matches!(label, "windows-1252" | "cp1252") {
        return latin1(bytes);
    }
    if let Some(text) = codec
        .and_then(|encoding| encoding.decode_without_bom_handling_and_without_replacement(&bytes))
    {
        // Undefined bytes in Windows code pages are mapped to C1 controls by
        // web decoders. An invalid byte triggers Latin-1 for the whole field.
        if !codec.is_some_and(|encoding| encoding.name().starts_with("windows-"))
            || !text.contains(|c| ('\u{80}'..='\u{9f}').contains(&c))
        {
            return text.into_owned();
        }
    }
    latin1(bytes)
}

fn wide(bytes: &[u8], width: usize, label: &str) -> Option<String> {
    let little = label.ends_with("le");
    let explicit = little || label.ends_with("be");
    let (little, data) = if explicit {
        (little, bytes)
    } else {
        match (width, bytes) {
            (4, [0xff, 0xfe, 0, 0, rest @ ..]) | (2, [0xff, 0xfe, rest @ ..]) => (true, rest),
            (4, [0, 0, 0xfe, 0xff, rest @ ..]) | (2, [0xfe, 0xff, rest @ ..]) => (false, rest),
            _ => (cfg!(target_endian = "little"), bytes),
        }
    };
    crate::request_json::encoding::wide_text(data, width, little).ok()
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn decodes_declared_charsets_and_falls_back_for_the_whole_field() {
        let text = "café".as_bytes();
        assert_eq!(decode(text.to_vec(), "UTF-8"), "café");
        for label in ["latin1", "ASCII", "unknown"] {
            assert_eq!(decode(text.to_vec(), label), "cafÃ©");
        }
        assert_eq!(decode(vec![0xa4], "iso-8859-15"), "€");
        assert_eq!(decode(vec![0x80], "Windows-1252"), "€");
        assert_eq!(decode(vec![0x81, 0x80], "cp1252"), "\u{81}\u{80}");
        assert_eq!(decode(vec![0x82, 0xa0], "shift_jis"), "あ");
    }
}
