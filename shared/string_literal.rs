use unicode_general_category::get_general_category;

pub(crate) fn quoted_string(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote || c == '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if unprintable(c) => {
                use std::fmt::Write;
                let n = c as u32;
                match n {
                    0..=255 => write!(out, "\\x{n:02x}"),
                    256..=65535 => write!(out, "\\u{n:04x}"),
                    _ => write!(out, "\\U{n:08x}"),
                }
                .expect("write to string");
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

pub(crate) fn unprintable(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_control();
    }
    use unicode_general_category::GeneralCategory::*;
    c != ' '
        && matches!(
            get_general_category(c),
            Control
                | Format
                | PrivateUse
                | Unassigned
                | LineSeparator
                | ParagraphSeparator
                | SpaceSeparator
        )
}
