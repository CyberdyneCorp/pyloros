//! Inspect a known transaction without loading a signer or submitting a mutation.
use super::{Chain, Value, json};
use alloy_primitives::B256;
use serde::Serialize;
use std::error::Error;

#[derive(Serialize)]
pub struct ReceiptObservation {
    pub requested_hash: B256,
    pub outcome: &'static str,
}

fn outcome(expected: B256, receipt: &Value) -> &'static str {
    if receipt.is_null() {
        return "receipt_unavailable";
    }
    let hash = receipt["transactionHash"]
        .as_str()
        .and_then(|value| value.parse::<B256>().ok());
    match hash {
        None => "invalid_receipt_hash",
        Some(actual) if actual != expected => "hash_mismatch",
        Some(_) => match receipt["status"].as_str() {
            Some("0x0") => "reported_revert",
            Some("0x1") => "reported_success",
            _ => "unknown_status",
        },
    }
}

pub async fn inspect_receipt(hash: &str) -> Result<ReceiptObservation, Box<dyn Error>> {
    let requested_hash = hash.parse::<B256>()?;
    let chain = Chain {
        endpoint: std::env::var("BLOCKCHAIN_RPC_ENDPOINT")?,
        identity: None,
        policy: None,
        group: None,
        signer: None,
        timeout: super::super::rpc_timeout()?,
    };
    let receipt = chain
        .rpc("eth_getTransactionReceipt", json!([requested_hash]))
        .await
        .map_err(|_| "Could not read transaction receipt from the configured RPC endpoint")?;
    Ok(ReceiptObservation {
        requested_hash,
        outcome: outcome(requested_hash, &receipt),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_only_the_requested_hash_and_standard_status() {
        let hash = B256::repeat_byte(7);
        for (receipt, expected) in [
            (Value::Null, "receipt_unavailable"),
            (json!({"status":"0x1"}), "invalid_receipt_hash"),
            (
                json!({"transactionHash":B256::ZERO,"status":"0x1"}),
                "hash_mismatch",
            ),
            (json!({"transactionHash":hash}), "unknown_status"),
            (
                json!({"transactionHash":hash,"status":"0x2"}),
                "unknown_status",
            ),
            (
                json!({"transactionHash":hash,"status":"0x0"}),
                "reported_revert",
            ),
            (
                json!({"transactionHash":hash,"status":"0x1"}),
                "reported_success",
            ),
        ] {
            assert_eq!(outcome(hash, &receipt), expected);
        }
    }
}
