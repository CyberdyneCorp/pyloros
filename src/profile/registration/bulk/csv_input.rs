use super::input::{Rejection, bad};
use super::internal;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};

const MAX_FIELD_CHARS: usize = 131_072;
const COLUMNS_ERROR: &str = "CSV must have \"email\" and \"password\" header columns";
fn io_error(error: io::Error) -> Rejection {
    if error.kind() == io::ErrorKind::InvalidData {
        bad("File must be UTF-8 encoded")
    } else {
        Box::new(internal())
    }
}

// Decode every physical line before reporting CSV structure errors. An invalid byte
// anywhere in the upload takes precedence over a missing header or a row limit.
fn inspect(source: &mut (impl Read + Seek)) -> Result<bool, Rejection> {
    source.rewind().map_err(io_error)?;
    let mut reader = BufReader::new(source);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(io_error)?;
    let header = line.strip_prefix('\u{feff}').unwrap_or(&line);
    let empty = header.is_empty();
    let blank = matches!(header, "\n" | "\r\n" | "\r");
    let mut bare_cr = false;
    loop {
        let text = line.strip_suffix("\r\n").unwrap_or(&line);
        bare_cr |= text.contains('\r');
        line.clear();
        if reader.read_line(&mut line).map_err(io_error)? == 0 {
            break;
        }
    }
    if empty {
        return Err(bad("CSV file is empty"));
    }
    if blank {
        return Err(bad(COLUMNS_ERROR));
    }
    reader.rewind().map_err(io_error)?;
    Ok(bare_cr)
}

pub(super) fn parse(mut source: impl Read + Seek) -> Result<Vec<(String, String)>, Rejection> {
    let bare_cr = inspect(&mut source)?;
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(source);
    let mut record = csv::StringRecord::new();
    if !next(&mut reader, &mut record, bare_cr)? {
        return Err(bad(COLUMNS_ERROR));
    }
    let column = |key| {
        (0..record.len())
            .rfind(|&index| trim(&record[index]).eq_ignore_ascii_case(key))
            .ok_or_else(|| bad(COLUMNS_ERROR))
    };
    let email = column("email")?;
    let password = column("password")?;
    let mut rows = Vec::new();
    let mut count = 0usize;
    while next(&mut reader, &mut record, bare_cr)? {
        count += 1;
        if count <= 1000 {
            rows.push((
                trim(record.get(email).unwrap_or("")).to_owned(),
                record.get(password).unwrap_or("").to_owned(),
            ));
        }
    }
    match count {
        0 => Err(bad("CSV contained no data rows")),
        1..=1000 => Ok(rows),
        _ => Err(bad(&format!("Too many rows: {count} (max 1000)"))),
    }
}
fn next(
    reader: &mut csv::Reader<impl Read + Seek>,
    record: &mut csv::StringRecord,
    bare_cr: bool,
) -> Result<bool, Rejection> {
    let found = reader
        .read_record(record)
        .map_err(|_| Box::new(internal()))?;
    let pos = reader.position().byte();
    if found
        && (record.iter().any(|s| s.chars().count() > MAX_FIELD_CHARS)
            || (bare_cr && invalid_terminator(reader.get_mut(), pos).map_err(io_error)?))
    {
        return Err(Box::new(internal()));
    }
    Ok(found)
}
// The CSV reader accepts lone CR record separators. The REST importer accepts CR
// inside a quoted field, but expects LF before the next physical line of data.
fn invalid_terminator(source: &mut (impl Read + Seek), pos: u64) -> io::Result<bool> {
    let saved = source.stream_position()?;
    source.seek(SeekFrom::Start(pos.saturating_sub(1)))?;
    let mut byte = [0u8; 1];
    let mut invalid = false;
    if source.read(&mut byte)? != 0 && byte[0] == b'\r' {
        while source.read(&mut byte)? != 0 {
            if byte[0] != b'\r' {
                invalid = byte[0] != b'\n';
                break;
            }
        }
    }
    source.seek(SeekFrom::Start(saved))?;
    Ok(invalid)
}
fn trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn recognizes_bom_duplicate_headers_and_embedded_newlines() {
        let file = "\u{feff}email,PASSWORD,email\r\nignored,\"line1\r\nline2\", owner@example.com \r\n\r\n,unquoted,second@example.com";
        assert_eq!(
            parse(Cursor::new(file)).unwrap(),
            [
                ("owner@example.com".into(), "line1\r\nline2".into()),
                ("second@example.com".into(), "unquoted".into())
            ]
        );
    }

    #[test]
    fn accepts_carriage_returns_inside_quotes_but_rejects_bare_record_separators() {
        let quoted = "email,password\na@example.org,\"one\rtwo\"\n";
        assert_eq!(parse(Cursor::new(quoted)).unwrap()[0].1, "one\rtwo");
        let invalid = "email,password\ra@example.org,wrong";
        assert_eq!(
            parse(Cursor::new(invalid)).unwrap_err().status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn field_limit_counts_decoded_characters_in_headers_and_data() {
        for length in [131_072, 131_073] {
            let header = "🌿".repeat(length);
            let quotes = "\"\"".repeat(length);
            for file in [
                format!("email,password,{header}\na@example.org,example\n"),
                format!("email,password,notes\na@example.org,example,ok\n,,\"{quotes}\"\n"),
            ] {
                let parsed = parse(Cursor::new(file));
                if length == 131_072 {
                    assert_eq!(
                        parsed.unwrap()[0],
                        ("a@example.org".into(), "example".into())
                    );
                } else {
                    assert_eq!(
                        parsed.unwrap_err().status(),
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR
                    );
                }
            }
        }
    }

    #[test]
    fn caps_nonempty_records_and_validates_the_entire_encoding() {
        let mut data = "email,password\n".to_owned() + &",\n".repeat(1000);
        assert_eq!(parse(Cursor::new(&data)).unwrap().len(), 1000);
        data.push_str(",\n");
        assert_eq!(
            parse(Cursor::new(&data)).unwrap_err().status(),
            axum::http::StatusCode::BAD_REQUEST
        );
        assert!(parse(Cursor::new(b"wrong,header\n\xff")).is_err());
    }
}
