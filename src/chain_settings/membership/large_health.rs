//! Spool larger health replies so ordinary extension fields can be skipped while parsing.
use super::{ReadError, RpcRead, rpc_response, transport};
use serde::{Deserialize, Deserializer, de::IgnoredAny};
use serde_json::{Value, value::RawValue};
use std::io::{BufReader, Read, Seek};
use tokio::io::AsyncWriteExt;

pub(super) async fn read(
    endpoint: &str,
    mut response: reqwest::Response,
    prefix: &[u8],
    chunk: &[u8],
) -> Result<Value, ReadError> {
    let file = tempfile::tempfile().map_err(|_| ReadError::Failure)?;
    let mut file = tokio::fs::File::from_std(file);
    file.write_all(prefix)
        .await
        .map_err(|_| ReadError::Failure)?;
    file.write_all(chunk)
        .await
        .map_err(|_| ReadError::Failure)?;
    while let Some(piece) = response
        .chunk()
        .await
        .map_err(|e| transport::request_error(endpoint, &e))?
    {
        file.write_all(&piece)
            .await
            .map_err(|_| ReadError::Failure)?;
    }
    file.flush().await.map_err(|_| ReadError::Failure)?;
    let file = file.into_std().await;
    tokio::task::spawn_blocking(move || decode(file))
        .await
        .map_err(|_| ReadError::Failure)?
}

#[derive(Deserialize)]
struct Success {
    jsonrpc: String,
    id: Box<RawValue>,
    result: Box<RawValue>,
    #[serde(rename = "error", default, deserialize_with = "present")]
    has_error: bool,
}

fn present<'de, D: Deserializer<'de>>(input: D) -> Result<bool, D::Error> {
    IgnoredAny::deserialize(input).map(|_| true)
}

fn decode(mut file: std::fs::File) -> Result<Value, ReadError> {
    file.rewind().map_err(|_| ReadError::Failure)?;
    if let Ok(success) = serde_json::from_reader::<_, Success>(BufReader::new(&file))
        && !success.has_error
        && success.jsonrpc == "2.0"
        && rpc_response::valid_health_id(&success.id, false)
    {
        return serde_json::from_str(success.result.get()).map_err(|_| ReadError::Failure);
    }
    // A malformed envelope can be quoted in the public diagnostic, including its extension fields.
    file.rewind().map_err(|_| ReadError::Failure)?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw).map_err(|_| ReadError::Failure)?;
    rpc_response::decode(&raw, RpcRead::Health)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn spooled_health_reply_skips_extensions_but_retains_them_in_format_errors() {
        let mut file = tempfile::tempfile().unwrap();
        write!(
            file,
            r#"{{"extra":"{}","id":"42","jsonrpc":"2.0","result":"0x02"}}"#,
            "x".repeat(1_100_000)
        )
        .unwrap();
        assert_eq!(decode(file).unwrap(), Value::String("0x02".into()));
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(br#"{"note":"before","jsonrpc":"2.0","id":1,"error":null,"result":null}"#)
            .unwrap();
        let Err(ReadError::Diagnostic(error)) = decode(file) else {
            panic!("expected invalid envelope")
        };
        assert!(error.contains("cannot include both"));
        assert!(error.contains("{'note': 'before', 'jsonrpc': '2.0'"));
    }
}
