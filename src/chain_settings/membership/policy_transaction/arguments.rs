//! Report identity-contract argument failures at the stage callers observe them.
use super::*;
use std::fmt::Write;

pub(super) fn incompatible_first(
    method: &str,
    types: &[&str],
    provided: &str,
    values: &[&str],
) -> PrepareError {
    let count = values.len();
    let signature = types.join(",");
    let mut detail = format!(
        "\nABI Not Found!\nFound 1 element(s) named `{method}` that accept {count} argument(s).\nThe provided arguments are not valid.\nProvided argument types: ({provided})\nProvided keyword argument types: {{}}\n\nTried to find a matching ABI element named `{method}`, but encountered the following problems:\nSignature: {method}({signature}), type: function\nArgument 1 value `{}` is not compatible with type `{}`.\n",
        values[0], types[0]
    );
    for (index, value) in values.iter().enumerate().skip(1) {
        writeln!(detail, "Argument {} value `{value}` is valid.", index + 1)
            .expect("write to string");
    }
    PrepareError::Argument(detail)
}

impl Chain {
    pub(crate) async fn prepare_mint_retry(
        &self,
        owner: &str,
        public_key: &str,
    ) -> Result<Vec<u8>, PrepareError> {
        if validate_address(owner).is_ok() {
            return self.prepare_identity_creation(owner, public_key, "").await;
        }
        let digits = owner
            .strip_prefix("0x")
            .or_else(|| owner.strip_prefix("0X"));
        if let Some(hex) = digits
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
            && hex.len() != 40
        {
            return Err(incompatible_first(
                "mint",
                &["address", "string", "string", "string"],
                "str,str,str,str",
                &[owner, public_key, "", ""],
            ));
        }
        let issue = owner_diagnostic(owner, digits).ok_or(PrepareError::Invalid)?;
        let address = self.identity.as_deref().ok_or(PrepareError::Unavailable)?;
        validate_address(address).map_err(|_| PrepareError::Unavailable)?;
        let signer = self.signer.as_deref().ok_or(PrepareError::Invalid)?;
        self.quantity("eth_getTransactionCount", json!([signer, "pending"]))
            .await?;
        Err(PrepareError::Argument(issue))
    }
}

fn owner_diagnostic(owner: &str, digits: Option<&str>) -> Option<String> {
    if digits.is_some_and(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())) {
        let message = if owner.bytes().any(|b| b.is_ascii_uppercase()) {
            "Address has an invalid EIP-55 checksum. After looking up the address from the original source, try again."
        } else {
            "web3.py only accepts checksum addresses. The software that gave you this non-checksum address should be considered unsafe, please file it as a bug on their platform. Try using an ENS name instead. Or, if you must accept lower safety, use Web3.to_checksum_address(lower_case_address)."
        };
        return Some(format!("('{message}', '{owner}')"));
    }
    if !owner.is_empty()
        && owner.bytes().all(|b| b.is_ascii_alphanumeric())
        && !(owner.len() == 40 && owner.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Some(format!("ENS name: '{owner}' is invalid."));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::post};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn malformed_hex_fails_before_nonce_lookup_and_checksum_failure_follows_it() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let seen = seen.clone();
                async move {
                    assert_eq!(request["method"], "eth_getTransactionCount");
                    seen.fetch_add(1, Ordering::Relaxed);
                    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":"0x1"}))
                }
            }),
        );
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = "0x0000000000000000000000000000000000000001".to_string();
        let chain = Chain {
            endpoint: format!("http://{}", socket.local_addr().unwrap()),
            identity: Some(address.clone()),
            signer: Some(address),
            group: None,
            policy: None,
            timeout: Duration::from_secs(2),
        };
        let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
        assert!(
            matches!(chain.prepare_mint_retry("0x123","key").await,Err(PrepareError::Argument(s)) if s.contains("Argument 1 value `0x123` is not compatible"))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(
            matches!(chain.prepare_mint_retry(&format!("0x{}","ab".repeat(20)),"key").await,Err(PrepareError::Argument(s)) if s.contains("only accepts checksum addresses"))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        server.abort();
    }
}
