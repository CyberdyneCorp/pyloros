//! Bounded decoding for provider HTTP documents.
use flate2::{Decompress, FlushDecompress, Status};
use reqwest::{Response, header::CONTENT_ENCODING};
use std::io;

const LIMIT: usize = 1024 * 1024;

fn append(bytes: &mut Vec<u8>, piece: &[u8]) -> io::Result<()> {
    if piece.len() > LIMIT - bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Provider document exceeds limit",
        ));
    }
    bytes.extend_from_slice(piece);
    Ok(())
}

pub(super) async fn read(mut response: Response) -> io::Result<Vec<u8>> {
    let deflate = response
        .headers()
        .get(CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"deflate"));
    if deflate {
        // A raw stream can begin with a valid zlib header. Keep each viable
        // interpretation until the format is known, without buffering the wire body.
        let mut wrapped = Some(Inflate::new(true));
        let mut raw = Some(Inflate::new(false));
        while let Some(piece) = response.chunk().await.map_err(io::Error::other)? {
            wrapped = wrapped.and_then(|decoder| decoder.feed(&piece));
            raw = raw.and_then(|decoder| decoder.feed(&piece));
            if wrapped.is_none() && raw.is_none() {
                break;
            }
        }
        return wrapped
            .and_then(Inflate::finish)
            .or_else(|| raw.and_then(Inflate::finish))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid or oversized deflate document",
                )
            });
    }
    let mut bytes = Vec::new();
    while let Some(piece) = response.chunk().await.map_err(io::Error::other)? {
        append(&mut bytes, &piece)?;
    }
    Ok(bytes)
}

struct Inflate {
    decoder: Decompress,
    bytes: Vec<u8>,
    complete: bool,
}

impl Inflate {
    fn new(wrapped: bool) -> Self {
        Self {
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
            append(&mut self.bytes, &output[..written]).ok()?;
            self.complete = status == Status::StreamEnd;
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
        self.complete.then_some(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    fn fragmented(data: &[u8], wrapped: bool) -> Option<Vec<u8>> {
        data.chunks(1)
            .try_fold(Inflate::new(wrapped), Inflate::feed)?
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
