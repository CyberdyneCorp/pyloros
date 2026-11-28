use super::{MAX_BYTES, dry_run, inspect};
use serde::Deserialize;
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
    check_hook_fixtures(component, &[(event, expected)]).await
}

/// Check every recorded outcome against the same bytes, even if the artifact is rebuilt.
pub async fn check_hook_fixtures(component: &Path, cases: &[(&Path, &Path)]) -> io::Result<String> {
    if cases.is_empty() {
        return Err(io::Error::other("Expected at least one hook fixture"));
    }
    let component = read_file(component, MAX_BYTES)?;
    inspect(&component).map_err(|_| io::Error::other("Invalid hook component"))?;
    for (index, &(event, expected)) in cases.iter().enumerate() {
        check_outcome(&component, event, expected)
            .await
            .map_err(|err| io::Error::new(err.kind(), format!("Fixture {}: {err}", index + 1)))?;
    }
    Ok(format!("{:x}", Sha256::digest(component)))
}

async fn check_outcome(component: &[u8], event: &Path, expected: &Path) -> io::Result<()> {
    let event = read_file(event, dry_run::MAX_EVENT)?;
    if !crate::json_syntax::valid_hook_event(&event) {
        return Err(io::Error::other("Invalid JSON event"));
    }
    let expected: Outcome = serde_json::from_slice(&read_file(expected, 1 << 20)?)
        .map_err(|_| io::Error::other("Expected a guest status and output string"))?;
    let result = tokio::time::timeout(Duration::from_secs(5), dry_run::invoke(component, &event))
        .await
        .map_err(|_| io::Error::other("Hook worker timed out"))??;
    let actual: Outcome =
        serde_json::from_value(result).map_err(|_| io::Error::other("Hook execution failed"))?;
    if actual != expected {
        return Err(io::Error::other("Hook outcome differs from fixture"));
    }
    Ok(())
}
