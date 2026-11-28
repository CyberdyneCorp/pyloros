//! Stream a receiver's nested HTTP content codings into the bounded history excerpt.
use flate2::{Decompress, FlushDecompress, Status};
use reqwest::{Response, header::CONTENT_ENCODING};
use std::io;

enum Layer {
    Deflate(Vec<u8>),
    Active(Decompress),
    End,
}

fn feed(layers: &mut [Layer], data: &[u8], excerpt: &mut Vec<u8>) -> io::Result<()> {
    let Some((layer, rest)) = layers.split_first_mut() else {
        excerpt.extend_from_slice(&data[..data.len().min(1024 - excerpt.len())]);
        return Ok(());
    };
    let mut input = data;
    if let Layer::Deflate(prefix) = layer {
        let count = (2 - prefix.len()).min(input.len());
        prefix.extend_from_slice(&input[..count]);
        input = &input[count..];
        if prefix.len() < 2 {
            return Ok(());
        }
        let header = [prefix[0], prefix[1]];
        let wrapped = header[0] & 15 == 8
            && header[0] >> 4 <= 7
            && u16::from_be_bytes(header).is_multiple_of(31);
        *layer = Layer::Active(Decompress::new(wrapped));
        inflate(layer, rest, &header, excerpt)?;
    }
    inflate(layer, rest, input, excerpt)
}

fn inflate(
    layer: &mut Layer,
    rest: &mut [Layer],
    mut input: &[u8],
    excerpt: &mut Vec<u8>,
) -> io::Result<()> {
    let Layer::Active(decoder) = layer else {
        return Ok(());
    };
    let mut output = [0; 8192];
    while excerpt.len() < 1024 {
        let before = (decoder.total_in(), decoder.total_out());
        let status = decoder.decompress(input, &mut output, FlushDecompress::None)?;
        let consumed = (decoder.total_in() - before.0) as usize;
        let produced = (decoder.total_out() - before.1) as usize;
        if produced > 0 {
            feed(rest, &output[..produced], excerpt)?;
        }
        if status == Status::StreamEnd {
            *layer = Layer::End;
            break;
        }
        input = &input[consumed..];
        if produced == 0 && consumed == 0 || input.is_empty() && produced < output.len() {
            break;
        }
    }
    Ok(())
}

pub(super) async fn read(response: Response) -> io::Result<Vec<u8>> {
    let encodings = response.headers().get_all(CONTENT_ENCODING);
    let mut fields = encodings.iter();
    let first = fields.next();
    if fields.next().is_none() && !first.is_some_and(|v| v.as_bytes().contains(&b',')) {
        return crate::http_body::read(response, crate::http_body::ReadLimit::Prefix(1024)).await;
    }
    let codings = encodings
        .iter()
        .flat_map(|header| header.as_bytes().split(|byte| *byte == b','))
        .map(<[u8]>::trim_ascii);
    let mut layers = Vec::new();
    for coding in codings {
        let layer = if coding.eq_ignore_ascii_case(b"gzip") {
            Layer::Active(Decompress::new_gzip(15))
        } else if coding.eq_ignore_ascii_case(b"deflate") {
            Layer::Deflate(Vec::new())
        } else {
            continue;
        };
        // Bound per-layer decoder state and nested feed calls.
        if layers.len() == 8 {
            return Err(io::Error::other("too many content codings"));
        }
        layers.push(layer);
    }
    if matches!(layers.as_slice(), [Layer::Deflate(_)]) {
        return crate::http_body::read_deflate(response, crate::http_body::ReadLimit::Prefix(1024))
            .await;
    }
    layers.reverse();
    let mut excerpt = Vec::new();
    let mut body = crate::http_body::WireBody::new(response);
    while let Some(chunk) = body.chunk().await? {
        feed(&mut layers, &chunk, &mut excerpt)?;
        if excerpt.len() == 1024 {
            break;
        }
    }
    Ok(excerpt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{
        Compression,
        write::{DeflateEncoder, GzEncoder, ZlibEncoder},
    };
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn decode_combined_and_repeated_fields_in_wire_order() {
        let text = "received λ".repeat(200);
        let mut wrapped = ZlibEncoder::new(Vec::new(), Compression::fast());
        wrapped.write_all(&gzip(text.as_bytes())).unwrap();
        let mut raw = DeflateEncoder::new(Vec::new(), Compression::fast());
        raw.write_all(text.as_bytes()).unwrap();
        for (headers, body) in [
            (vec!["gzip, deflate"], wrapped.finish().unwrap()),
            (vec!["deflate", "gzip"], gzip(&raw.finish().unwrap())),
        ] {
            let mut reply = axum::http::Response::builder();
            for header in headers {
                reply = reply.header(CONTENT_ENCODING, header);
            }
            let response = reply.body(reqwest::Body::from(body)).unwrap().into();
            assert_eq!(read(response).await.unwrap(), &text.as_bytes()[..1024]);
        }
    }

    #[tokio::test]
    async fn identity_coding_preserves_raw_deflate_acknowledgements() {
        // Two stored blocks whose first bytes also satisfy the zlib header check.
        let body = [0x78, 1, 0, 254, 255, b'o', 1, 1, 0, 254, 255, b'k'];
        for fields in [vec!["identity, deflate"], vec!["deflate", "identity"]] {
            let mut builder = axum::http::Response::builder();
            for field in fields {
                builder = builder.header(CONTENT_ENCODING, field);
            }
            let response = builder.body(reqwest::Body::from(body.to_vec())).unwrap();
            assert_eq!(read(response.into()).await.unwrap(), b"ok");
        }
    }

    #[tokio::test]
    async fn enforce_decoder_depth_before_processing_the_body() {
        for count in [8, 9] {
            let mut body = b"ok".to_vec();
            for _ in 0..count {
                body = gzip(&body);
            }
            let response = axum::http::Response::builder()
                .header(CONTENT_ENCODING, vec!["gzip"; count].join(", "))
                .body(reqwest::Body::from(body))
                .unwrap()
                .into();
            let result = read(response).await;
            if count == 8 {
                assert_eq!(result.unwrap(), b"ok");
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn handle_single_byte_chunks_between_layers() {
        let expected = b"acknowledged";
        let mut data = ZlibEncoder::new(Vec::new(), Compression::fast());
        data.write_all(&gzip(expected)).unwrap();
        let mut layers = [
            Layer::Deflate(Vec::new()),
            Layer::Active(Decompress::new_gzip(15)),
        ];
        let mut excerpt = Vec::new();
        for byte in data.finish().unwrap() {
            feed(&mut layers, &[byte], &mut excerpt).unwrap();
        }
        assert_eq!(excerpt, expected);
    }
}
