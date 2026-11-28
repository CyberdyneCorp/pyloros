//! Decode the selected form part before interpreting the CSV as an operator.
mod charset;
mod disposition;
use super::*;
use axum::extract::FromRequest;
use futures_util::StreamExt;

use tokio::io::AsyncWriteExt;

pub(super) enum Upload {
    Missing,
    Text(String),
    File(std::fs::File),
}
pub(super) type Rejection = Box<Response>;
pub(super) fn bad(message: &str) -> Rejection {
    Box::new(problem(StatusCode::BAD_REQUEST, message))
}
fn malformed() -> Rejection {
    bad("There was an error parsing the body")
}

pub(super) async fn envelope(req: Request) -> Result<Upload, Rejection> {
    let media = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media == "application/x-www-form-urlencoded" {
        let bytes = axum::body::Bytes::from_request(req, &())
            .await
            .map_err(|_| malformed())?;
        return Ok(url::form_urlencoded::parse(&bytes)
            .filter(|(k, _)| k == "file")
            .last()
            .map_or(Upload::Missing, |(_, v)| Upload::Text(v.into_owned())));
    }
    if media != "multipart/form-data" {
        return Ok(Upload::Missing);
    }
    multipart(req).await
}

async fn multipart(req: Request) -> Result<Upload, Rejection> {
    let media = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<mime::Mime>().ok())
        .ok_or_else(|| bad("Missing boundary in multipart."))?;
    let boundary = media
        .get_param(mime::BOUNDARY)
        .ok_or_else(|| bad("Missing boundary in multipart."))?;
    let charset = media
        .get_param(mime::CHARSET)
        .map_or("utf-8", |value| value.as_str());
    let mut body = req.into_body().into_data_stream();
    let first = loop {
        match body.next().await {
            Some(Ok(bytes)) if bytes.is_empty() => continue,
            Some(chunk) => break chunk,
            None => return Ok(Upload::Missing),
        }
    };
    let stream = futures_util::stream::once(async { first }).chain(body);
    let mut form = multer::Multipart::new(stream, boundary.as_str());
    select_file(&mut form, charset).await
}

async fn select_file(form: &mut multer::Multipart<'_>, charset: &str) -> Result<Upload, Rejection> {
    let mut selected = Upload::Missing;
    let mut files = 0;
    let mut fields = 0;
    while let Some(part) = form.next_field().await.map_err(|_| malformed())? {
        let (wanted, is_file) = part
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|header| disposition::classify(header.as_bytes(), charset))
            .ok_or_else(|| {
                bad("The Content-Disposition header field \"name\" must be provided.")
            })?;
        let result = if is_file {
            count_part(&mut files, "files")?;
            read_file(part, wanted).await?
        } else {
            count_part(&mut fields, "fields")?;
            text_field(part, wanted, charset).await?
        };
        match result {
            None => break,
            Some(Upload::Missing) => continue,
            Some(value) => selected = value,
        }
    }
    Ok(selected)
}

fn count_part(count: &mut usize, kind: &str) -> Result<(), Rejection> {
    *count += 1;
    if *count > 1000 {
        return Err(bad(&format!(
            "Too many {kind}. Maximum number of {kind} is 1000."
        )));
    }
    Ok(())
}

async fn read_file(mut part: multer::Field<'_>, wanted: bool) -> Result<Option<Upload>, Rejection> {
    let mut out = if wanted {
        let file = tempfile::tempfile().map_err(|_| Box::new(internal()))?;
        Some(tokio::fs::File::from_std(file))
    } else {
        None
    };
    while let Some(chunk) = match part.chunk().await {
        Ok(chunk) => chunk,
        Err(multer::Error::IncompleteFieldData { .. }) => return Ok(None),
        Err(_) => return Err(malformed()),
    } {
        if let Some(file) = &mut out {
            file.write_all(&chunk)
                .await
                .map_err(|_| Box::new(internal()))?;
        }
    }
    let Some(mut file) = out else {
        return Ok(Some(Upload::Missing));
    };
    file.flush().await.map_err(|_| Box::new(internal()))?;
    Ok(Some(Upload::File(file.into_std().await)))
}

async fn text_field(
    mut part: multer::Field<'_>,
    wanted: bool,
    charset: &str,
) -> Result<Option<Upload>, Rejection> {
    let mut size = 0;
    let mut data = Vec::new();
    while let Some(chunk) = match part.chunk().await {
        Ok(chunk) => chunk,
        Err(multer::Error::IncompleteFieldData { .. }) => return Ok(None),
        Err(_) => return Err(malformed()),
    } {
        size += chunk.len();
        if size > 1024 * 1024 {
            return Err(bad("Part exceeded maximum size of 1024KB."));
        }
        if wanted {
            data.extend_from_slice(&chunk);
        }
    }
    if !wanted {
        return Ok(Some(Upload::Missing));
    }
    let text = charset::decode(data, charset);
    Ok(Some(Upload::Text(text)))
}

pub(super) async fn records(upload: Upload) -> Result<Vec<(String, String)>, Rejection> {
    let issue = match upload {
        Upload::File(file) => {
            return tokio::task::spawn_blocking(move || super::csv_input::parse(file))
                .await
                .map_err(|_| Box::new(internal()))?;
        }
        Upload::Text(s) if !s.is_empty() => {
            let msg = "Expected UploadFile, received: <class 'str'>";
            json!({"loc":["body","file"],"type":"value_error","msg":format!("Value error, {msg}"),"input":s,"ctx":{"error":msg}})
        }
        _ => json!({"loc":["body","file"],"type":"missing","msg":"Field required","input":null}),
    };
    Err(Box::new(password_change::invalid(vec![issue])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    async fn decode(bytes: &str) -> Upload {
        let req = Request::builder()
            .header(header::CONTENT_TYPE, "multipart/form-data; boundary=abc")
            .body(Body::from(bytes.to_owned()))
            .unwrap();
        envelope(req).await.unwrap()
    }

    #[tokio::test]
    async fn envelope_charset_affects_field_selection_but_preserves_csv_bytes() {
        let csv = "--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"staff.csv\"\r\n\r\nemail,password\r\nélise@example.org,example\r\n--abc--\r\n";
        for (charset, selected) in [("utf-16le", false), ("utf-32", true), ("cp1252", true)] {
            let req = Request::builder()
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary=abc; charset={charset}"),
                )
                .body(Body::from(csv))
                .unwrap();
            let upload = envelope(req).await.unwrap();
            if selected {
                assert_eq!(records(upload).await.unwrap()[0].0, "élise@example.org");
            } else {
                assert!(matches!(upload, Upload::Missing));
            }
        }
    }

    #[tokio::test]
    async fn only_completed_form_parts_replace_the_selected_value() {
        assert!(matches!(decode("").await, Upload::Missing));
        for disposition in [
            "name=\"file\"; filename=\"partial.csv\"",
            "name=\"file\"",
            "name=\"unused\"; filename=\"other\"",
        ] {
            let form = format!(
                "--abc\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nfirst\r\n--abc\r\nContent-Disposition: form-data; {disposition}\r\n\r\npartial"
            );
            assert!(matches!(decode(&form).await, Upload::Text(text) if text == "first"));
        }
    }
}
