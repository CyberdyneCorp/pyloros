//! Inspect a known transaction without loading a signer or submitting a mutation.
use super::inspection::inspection_chain;
use super::{Chain, Value, json};
use alloy_primitives::B256;
use serde::Serialize;
use std::{error::Error, time::Duration};

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

impl Chain {
    async fn observe_receipt(&self, hash: B256, poll: bool) -> Result<&'static str, &'static str> {
        loop {
            let receipt = self
                .rpc("eth_getTransactionReceipt", json!([hash]))
                .await
                .map_err(
                    |_| "Could not read transaction receipt from the configured RPC endpoint",
                )?;
            if !poll || !receipt.is_null() {
                return Ok(outcome(hash, &receipt));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn wait_for_receipt(
        &self,
        hash: B256,
        limit: Duration,
    ) -> Result<&'static str, &'static str> {
        tokio::time::timeout(limit, self.observe_receipt(hash, true))
            .await
            .unwrap_or(Ok("receipt_timeout"))
    }
}

pub async fn inspect_receipt(hash: &str) -> Result<ReceiptObservation, Box<dyn Error>> {
    let requested_hash = hash.parse::<B256>()?;
    let outcome = inspection_chain()?
        .observe_receipt(requested_hash, false)
        .await?;
    Ok(ReceiptObservation {
        requested_hash,
        outcome,
    })
}

pub async fn wait_for_receipt(hash: &str) -> Result<ReceiptObservation, Box<dyn Error>> {
    let requested_hash = hash.parse::<B256>()?;
    let outcome = inspection_chain()?
        .wait_for_receipt(requested_hash, Duration::from_secs(60))
        .await?;
    Ok(ReceiptObservation {
        requested_hash,
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
            .wait_for_receipt(B256::ZERO, Duration::from_millis(100))
            .await
            .unwrap();
        server.abort();
        assert_eq!(outcome, "receipt_timeout");
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
            assert_eq!(outcome(hash, &receipt), expected);
        }
    }
}
