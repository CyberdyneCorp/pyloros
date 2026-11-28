//! Select form parts from their raw Content-Disposition parameters.
use super::charset;

/// Returns whether this is the requested field and whether it carries a file.
pub(super) fn classify(header: &[u8], charset: &str) -> Option<(bool, bool)> {
    let mut name = None;
    let mut has_filename = false;
    for parameter in parameters(header).skip(1) {
        let mut pair = parameter.splitn(2, |c| *c == b'=');
        let key = pair.next()?.trim_ascii();
        if key.eq_ignore_ascii_case(b"name") {
            name = Some(pair.next().unwrap_or_default().trim_ascii());
        } else if key.eq_ignore_ascii_case(b"filename") {
            has_filename = true;
        }
    }
    let name = name?;
    let name = name
        .strip_prefix(b"\"")
        .and_then(|v| v.strip_suffix(b"\""))
        .unwrap_or(name);
    Some((
        charset::decode(name.to_vec(), charset) == "file",
        has_filename,
    ))
}

fn parameters(header: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut quoted = false;
    let mut escaped = false;
    header.split(move |&byte| {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        }
        byte == b';' && !quoted
    })
}

#[cfg(test)]
mod tests {
    use super::classify;

    #[test]
    fn recognizes_file_parameters_independently_of_filename_encoding() {
        assert_eq!(
            classify(b"form-data; FILENAME=\"caf\xe9.csv\"; NAME=file", "latin1"),
            Some((true, true))
        );
        assert_eq!(
            classify(b"form-data; name=file; filename=\"\"", "utf-8"),
            Some((true, true))
        );
        assert_eq!(
            classify(b"form-data; name=\"caf\xe9\"", "latin1"),
            Some((false, false))
        );
    }

    #[test]
    fn selects_the_last_name_and_keeps_quoted_parameters_together() {
        let header = br#"form-data; name=other; note="a\"; filename=ghost"; name="file""#;
        assert_eq!(classify(header, "utf-8"), Some((true, false)));
        assert_eq!(
            classify(b"form-data; name=file; name=other; filename=a", "utf-8"),
            Some((false, true))
        );
        assert_eq!(
            classify(br#"form-data; filename="x; name=file""#, "utf-8"),
            None
        );
    }
}
