//! Bounded decoding for complete HTTP documents and receiver response excerpts.
use flate2::{Decompress, FlushDecompress, Status};
use reqwest::{Response, header::CONTENT_ENCODING};
use std::io;

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
    let deflate = response
        .headers()
        .get(CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"deflate"));
    if deflate {
        return read_deflate(response, limit).await;
    }
    let mut bytes = Vec::new();
    while let Some(piece) = response.chunk().await.map_err(io::Error::other)? {
        if limit.append(&mut bytes, &piece)? {
            break;
        }
    }
    Ok(bytes)
}

async fn read_deflate(mut response: Response, limit: ReadLimit) -> io::Result<Vec<u8>> {
    // A raw stream can begin with a valid zlib header. Keep each viable
    // interpretation until the format is known, without buffering the wire body.
    let mut wrapped = Some(Inflate::new(true, limit));
    let mut raw = Some(Inflate::new(false, limit));
    while let Some(piece) = response.chunk().await.map_err(io::Error::other)? {
        wrapped = wrapped.and_then(|decoder| decoder.feed(&piece));
        raw = raw.and_then(|decoder| decoder.feed(&piece));
        if let ReadLimit::Prefix(size) = limit
            && wrapped
                .as_ref()
                .or(raw.as_ref())
                .is_some_and(|decoder| decoder.bytes.len() == size)
        {
            break;
        }
        if wrapped.is_none() && raw.is_none() {
            break;
        }
    }
    wrapped
        .and_then(Inflate::finish)
        .or_else(|| raw.and_then(Inflate::finish))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid or oversized deflate document",
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
    fn new(wrapped: bool, limit: ReadLimit) -> Self {
        Self {
            limit,
            decoder: Decompress::new(wrapped),
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
        let empty_response =
            matches!(self.limit, ReadLimit::Prefix(_)) && self.decoder.total_in() == 0;
        (self.complete || empty_response).then_some(self.bytes)
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
                Inflate::new(wrapped, ReadLimit::Complete(1024)),
                Inflate::feed,
            )?
            .finish()
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
