//! Bounded decoding for complete HTTP documents and receiver response excerpts.
use flate2::{Decompress, FlushDecompress, Status};
use reqwest::{Response, header::CONTENT_ENCODING};
use std::{error::Error, io};

#[derive(Debug, thiserror::Error)]
#[error(
    "peer closed connection without sending complete message body (received {received} bytes, expected {expected})"
)]
pub(crate) struct ShortBody {
    received: usize,
    expected: u64,
}

fn body_error(error: reqwest::Error, received: usize, expected: Option<u64>) -> io::Error {
    if let Some(expected) = expected {
        let eof = std::iter::successors(error.source(), |cause| (*cause).source()).any(|cause| {
            cause
                .downcast_ref::<io::Error>()
                .is_some_and(|io| io.kind() == io::ErrorKind::UnexpectedEof)
        });
        if eof {
            return io::Error::new(
                io::ErrorKind::UnexpectedEof,
                ShortBody { received, expected },
            );
        }
    }
    io::Error::other(error)
}

#[derive(Clone, Copy)]
pub(crate) enum ReadLimit {
    Complete(usize),
    Prefix(usize),
}

impl ReadLimit {
    fn append(self, bytes: &mut Vec<u8>, piece: &[u8]) -> io::Result<bool> {
        match self {
            Self::Prefix(limit) => {
                let keep = piece.len().min(limit - bytes.len());
                bytes.extend_from_slice(&piece[..keep]);
                Ok(bytes.len() == limit)
            }
            Self::Complete(limit) if piece.len() > limit - bytes.len() => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP body exceeds limit",
            )),
            Self::Complete(_) => {
                bytes.extend_from_slice(piece);
                Ok(false)
            }
        }
    }
}

pub(crate) async fn read(mut response: Response, limit: ReadLimit) -> io::Result<Vec<u8>> {
    let coding = response
        .headers()
        .get(CONTENT_ENCODING)
        .map(|value| value.as_bytes())
        .unwrap_or_default();
    if coding.eq_ignore_ascii_case(b"gzip") {
        return read_compressed(response, limit, Decompress::new_gzip(15), None).await;
    }
    if coding.eq_ignore_ascii_case(b"deflate") {
        // Raw deflate can start with a valid zlib header. Keep both viable
        // interpretations without buffering the wire body.
        return read_compressed(
            response,
            limit,
            Decompress::new(true),
            Some(Decompress::new(false)),
        )
        .await;
    }
    let expected = response.content_length();
    let mut bytes = Vec::new();
    while let Some(piece) = response
        .chunk()
        .await
        .map_err(|e| body_error(e, bytes.len(), expected))?
    {
        if limit.append(&mut bytes, &piece)? {
            break;
        }
    }
    Ok(bytes)
}

async fn read_compressed(
    mut response: Response,
    limit: ReadLimit,
    framed: Decompress,
    raw: Option<Decompress>,
) -> io::Result<Vec<u8>> {
    let mut framed = Some(Inflate::new(framed, limit));
    let mut raw = raw.map(|decoder| Inflate::new(decoder, limit));
    while let Some(piece) = response.chunk().await.map_err(io::Error::other)? {
        framed = framed.and_then(|decoder| decoder.feed(&piece));
        raw = raw.and_then(|decoder| decoder.feed(&piece));
        if let ReadLimit::Prefix(size) = limit
            && framed
                .as_ref()
                .or(raw.as_ref())
                .is_some_and(|decoder| decoder.bytes.len() == size)
        {
            break;
        }
        if framed.is_none() && raw.is_none() {
            break;
        }
    }
    // Prefer a finished raw stream over an unfinished zlib interpretation.
    let decoder = match (&framed, &raw) {
        (Some(framed), Some(raw_decoder)) if raw_decoder.complete && !framed.complete => raw,
        _ => framed.or(raw),
    };
    decoder.and_then(Inflate::finish).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid or oversized compressed document",
        )
    })
}

struct Inflate {
    decoder: Decompress,
    limit: ReadLimit,
    bytes: Vec<u8>,
    complete: bool,
}

impl Inflate {
    fn new(decoder: Decompress, limit: ReadLimit) -> Self {
        Self {
            limit,
            decoder,
            bytes: Vec::new(),
            complete: false,
        }
    }

    fn feed(mut self, mut input: &[u8]) -> Option<Self> {
        let mut output = [0; 8192];
        while !self.complete {
            let consumed = self.decoder.total_in();
            let produced = self.decoder.total_out();
            let status = self
                .decoder
                .decompress(input, &mut output, FlushDecompress::None)
                .ok()?;
            let read = (self.decoder.total_in() - consumed) as usize;
            let written = (self.decoder.total_out() - produced) as usize;
            let full = self
                .limit
                .append(&mut self.bytes, &output[..written])
                .ok()?;
            self.complete = full || status == Status::StreamEnd;
            input = &input[read..];
            if read == 0 && written == 0 {
                return input.is_empty().then_some(self);
            }
            if input.is_empty() && written < output.len() {
                break;
            }
        }
        Some(self)
    }

    fn finish(self) -> Option<Vec<u8>> {
        (self.complete || matches!(self.limit, ReadLimit::Prefix(_))).then_some(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    #[tokio::test]
    async fn receiver_stops_at_the_decoded_prefix_even_when_the_connection_stays_open() {
        use axum::{
            Router,
            body::{Body, Bytes},
            http::Response,
            routing::get,
        };
        use futures_util::{StreamExt, stream};
        use std::{convert::Infallible, time::Duration};
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&[b'x'; 2048]).unwrap();
        let compressed = Bytes::from(encoder.finish().unwrap());
        let app = Router::new().route(
            "/",
            get(move || async move {
                let body = stream::iter([Ok::<_, Infallible>(compressed)]).chain(stream::pending());
                Response::builder()
                    .header(CONTENT_ENCODING, "deflate")
                    .body(Body::from_stream(body))
                    .unwrap()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let response = reqwest::Client::builder()
            .no_proxy()
            .no_deflate()
            .build()
            .unwrap()
            .get(url)
            .send()
            .await
            .unwrap();
        let bytes = tokio::time::timeout(
            Duration::from_secs(2),
            read(response, ReadLimit::Prefix(1024)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(bytes, vec![b'x'; 1024]);
        server.abort();
    }

    fn fragmented(data: &[u8], wrapped: bool) -> Option<Vec<u8>> {
        data.chunks(1)
            .try_fold(
                Inflate::new(Decompress::new(wrapped), ReadLimit::Complete(1024)),
                Inflate::feed,
            )?
            .finish()
    }

    #[test]
    fn gzip_excerpt_accepts_a_missing_trailer_and_rejects_a_bad_checksum() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(b"received").unwrap();
        let mut bytes = encoder.finish().unwrap();
        let trailer = bytes.len() - 8;
        let excerpt = |wire: &[u8]| {
            wire.chunks(1)
                .try_fold(
                    Inflate::new(Decompress::new_gzip(15), ReadLimit::Prefix(1024)),
                    Inflate::feed,
                )?
                .finish()
        };
        assert_eq!(
            excerpt(&bytes[..trailer]).as_deref(),
            Some(b"received".as_slice())
        );
        bytes[trailer] ^= 1;
        assert!(excerpt(&bytes).is_none());
    }

    #[test]
    fn unfinished_deflate_yields_an_excerpt_but_cannot_finish_a_document() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(b"ok").unwrap();
        encoder.flush().unwrap();
        let wrapped = encoder.get_ref();
        // One nonfinal raw stored block containing the same two bytes.
        let raw = [0, 2, 0, 253, 255, b'o', b'k'];
        for (bytes, zlib) in [(wrapped.as_slice(), true), (raw.as_slice(), false)] {
            let prefix = bytes
                .chunks(1)
                .try_fold(
                    Inflate::new(Decompress::new(zlib), ReadLimit::Prefix(1024)),
                    Inflate::feed,
                )
                .unwrap();
            assert_eq!(prefix.finish().as_deref(), Some(b"ok".as_slice()));
            assert!(fragmented(bytes, zlib).is_none());
        }
    }

    #[test]
    fn accepts_fragmented_streams_and_rejects_corrupt_or_partial_frames() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(b"{}").unwrap();
        let mut encoded = encoder.finish().unwrap();
        assert_eq!(fragmented(&encoded, true).unwrap(), b"{}");
        assert!(fragmented(&encoded[..encoded.len() - 1], true).is_none());
        *encoded.last_mut().unwrap() ^= 1;
        assert!(fragmented(&encoded, true).is_none());
        // A nonfinal stored block with padding, followed by a final stored block.
        // The first two bytes are also a valid zlib header.
        let raw = [0x78, 1, 0, 254, 255, b'{', 1, 1, 0, 254, 255, b'}'];
        assert_eq!(fragmented(&raw, false).unwrap(), b"{}");
        assert!(fragmented(&raw, true).is_none());
        assert!(fragmented(&raw[..raw.len() - 1], false).is_none());
    }
}
