//! Decode the Unicode encodings accepted for JSON request bodies.
use std::borrow::Cow;

pub(crate) fn text(bytes: &[u8]) -> Result<Cow<'_, str>, ()> {
    let (width, little, skip) = match bytes {
        [0xff, 0xfe, 0, 0, ..] => (4, true, 4),
        [0, 0, 0xfe, 0xff, ..] => (4, false, 4),
        [0xff, 0xfe, ..] => (2, true, 2),
        [0xfe, 0xff, ..] => (2, false, 2),
        [0, 0, _, _, ..] => (4, false, 0),
        [_, 0, 0, 0, ..] => (4, true, 0),
        [0, _, ..] => (2, false, 0),
        [_, 0, ..] => (2, true, 0),
        _ => {
            return std::str::from_utf8(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
                .map(Cow::Borrowed)
                .map_err(|_| ());
        }
    };
    let bytes = &bytes[skip..];
    if !bytes.len().is_multiple_of(width) {
        return Err(());
    }
    let text = if width == 2 {
        let units = bytes.chunks_exact(2).map(|s| {
            let pair = [s[0], s[1]];
            if little {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            }
        });
        char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .map_err(|_| ())?
    } else {
        bytes
            .chunks_exact(4)
            .map(|s| {
                let word = [s[0], s[1], s[2], s[3]];
                char::from_u32(if little {
                    u32::from_le_bytes(word)
                } else {
                    u32::from_be_bytes(word)
                })
                .ok_or(())
            })
            .collect::<Result<String, _>>()?
    };
    Ok(Cow::Owned(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_json_retains_supplementary_characters() {
        let input = r#"{"name":"🏛"}"#;
        let utf16: Vec<_> = [0xfe, 0xff]
            .into_iter()
            .chain(input.encode_utf16().flat_map(u16::to_be_bytes))
            .collect();
        let utf32: Vec<_> = input
            .chars()
            .flat_map(|c| u32::from(c).to_le_bytes())
            .collect();
        assert_eq!(text(&utf16).unwrap(), input);
        assert_eq!(text(&utf32).unwrap(), input);
        assert!(text(&utf16[..utf16.len() - 1]).is_err());
        assert!(text(&[0, 0, 0xfe, 0xff, 0, 0x11, 0, 0]).is_err());
    }
}
