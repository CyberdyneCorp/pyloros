//! Inspect a known transaction without loading a signer or submitting a mutation.
use super::inspection::inspection_chain;
use super::{Chain, ReadError, Value, json};
use alloy_primitives::{Address, B256};
use serde::Serialize;
use std::{error::Error, time::Duration};

#[derive(Serialize)]
pub struct ReceiptObservation {
    pub requested_hash: B256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_contract: Option<Address>,
    pub outcome: &'static str,
}

fn outcome(expected: B256, contract: Option<Address>, receipt: &Value) -> &'static str {
    if receipt.is_null() {
        return "receipt_unavailable";
    }
    let Some(hash) = receipt["transactionHash"]
        .as_str()
        .and_then(|s| s.parse::<B256>().ok())
    else {
        return "invalid_receipt_hash";
    };
    if hash != expected {
        return "hash_mismatch";
    }
    if let Some(contract) = contract {
        let Some(destination) = receipt["to"]
            .as_str()
            .and_then(|s| s.parse::<Address>().ok())
        else {
            return "invalid_receipt_destination";
        };
        if destination != contract {
            return "destination_mismatch";
        }
    }
    match receipt["status"].as_str() {
        Some("0x0") => "reported_revert",
        Some("0x1") => "reported_success",
        _ => "unknown_status",
    }
}

impl Chain {
    async fn observe_receipt(
        &self,
        hash: B256,
        contract: Option<Address>,
        poll: bool,
    ) -> Result<(&'static str, Value), ReadError> {
        loop {
            let receipt = self.rpc("eth_getTransactionReceipt", json!([hash])).await?;
            if !poll || !receipt.is_null() {
                return Ok((outcome(hash, contract, &receipt), receipt));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub(super) async fn wait_for_receipt(
        &self,
        hash: B256,
        contract: Option<Address>,
        limit: Duration,
    ) -> Result<(&'static str, Value), ReadError> {
        tokio::time::timeout(limit, self.observe_receipt(hash, contract, true))
            .await
            .unwrap_or(Ok(("receipt_timeout", Value::Null)))
    }
}

pub async fn inspect_receipt(hash: &str) -> Result<ReceiptObservation, Box<dyn Error>> {
    inspect_receipt_for(hash, None, false).await
}

pub async fn wait_for_receipt(hash: &str) -> Result<ReceiptObservation, Box<dyn Error>> {
    inspect_receipt_for(hash, None, true).await
}

pub async fn inspect_receipt_for(
    hash: &str,
    contract: Option<Address>,
    wait: bool,
) -> Result<ReceiptObservation, Box<dyn Error>> {
    let requested_hash = hash.parse::<B256>()?;
    let chain = inspection_chain()?;
    let (outcome, _) = if wait {
        chain
            .wait_for_receipt(requested_hash, contract, Duration::from_secs(60))
            .await
    } else {
        chain.observe_receipt(requested_hash, contract, false).await
    }
    .map_err(|_| "Could not read transaction receipt from the configured RPC endpoint")?;
    Ok(ReceiptObservation {
        requested_hash,
        requested_contract: contract,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_deadline_includes_an_inflight_read() {
        use axum::{Router, routing::post};
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let chain = Chain::for_health_test(format!("http://{}", socket.local_addr().unwrap()));
        let app = Router::new().route(
            "/",
            post(|| async { std::future::pending::<String>().await }),
        );
        let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
        let outcome = chain
            .wait_for_receipt(B256::ZERO, None, Duration::from_millis(100))
            .await
            .unwrap();
        server.abort();
        assert_eq!(outcome, ("receipt_timeout", Value::Null));
    }

    #[test]
    fn constrained_receipts_require_the_requested_destination() {
        let hash = B256::repeat_byte(7);
        let address = Address::repeat_byte(9);
        for (to, expected) in [
            (json!(address), "reported_success"),
            (json!(Address::ZERO), "destination_mismatch"),
            (Value::Null, "invalid_receipt_destination"),
            (json!("malformed"), "invalid_receipt_destination"),
        ] {
            let receipt = json!({"transactionHash":hash,"status":"0x1","to":to});
            assert_eq!(outcome(hash, Some(address), &receipt), expected);
        }
    }

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
            assert_eq!(outcome(hash, None, &receipt), expected);
        }
    }
}
