use super::{MAX_BYTES, dry_run, inspect};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    time::Duration,
};

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Status {
    Success,
    Error,
}

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Outcome {
    status: Status,
    output: String,
}

fn read_file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("Fixture file exceeds size limit"));
    }
    Ok(bytes)
}

/// Verify the exact guest outcome with the same isolated worker used by the API.
pub async fn check_hook_fixture(
    component: &Path,
    event: &Path,
    expected: &Path,
) -> io::Result<String> {
    let component = read_file(component, MAX_BYTES)?;
    inspect(&component).map_err(|_| io::Error::other("Invalid hook component"))?;
    let event = read_file(event, dry_run::MAX_EVENT)?;
    serde_json::from_slice::<Value>(&event).map_err(|_| io::Error::other("Invalid JSON event"))?;
    let expected: Outcome = serde_json::from_slice(&read_file(expected, 1 << 20)?)
        .map_err(|_| io::Error::other("Expected a guest status and output string"))?;
    let result = tokio::time::timeout(Duration::from_secs(5), dry_run::invoke(&component, &event))
        .await
        .map_err(|_| io::Error::other("Hook worker timed out"))??;
    let actual: Outcome =
        serde_json::from_value(result).map_err(|_| io::Error::other("Hook execution failed"))?;
    if actual != expected {
        return Err(io::Error::other("Hook outcome differs from fixture"));
    }
    Ok(format!("{:x}", Sha256::digest(component)))
}
