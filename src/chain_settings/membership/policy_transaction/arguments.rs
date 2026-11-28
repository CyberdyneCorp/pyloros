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
    pub(crate) async fn mint_retry(
        &self,
        owner: &str,
        public_key: &str,
    ) -> Result<(String, Option<TokenId>), PrepareError> {
        if validate_address(owner).is_ok() {
            return self.mint_identity(owner, public_key, "").await;
        }
        let issue = owner_diagnostic(owner).ok_or_else(|| {
            let provided = if validate_address(public_key).is_ok() {
                "str,address,str,str"
            } else {
                "str,str,str,str"
            };
            incompatible_first(
                "mint",
                &["address", "string", "string", "string"],
                provided,
                &[owner, public_key, "", ""],
            )
        })?;
        let address = self.identity.as_deref().ok_or(PrepareError::Unavailable)?;
        validate_address(address).map_err(|_| PrepareError::Unavailable)?;
        let signer = self.signer.as_deref().ok_or(PrepareError::Invalid)?;
        self.quantity("eth_getTransactionCount", json!([signer, "pending"]))
            .await?;
        Err(PrepareError::Argument(issue))
    }
}

fn owner_diagnostic(owner: &str) -> Option<String> {
    let digits = owner
        .strip_prefix("0x")
        .or_else(|| owner.strip_prefix("0X"));
    let hex = digits.unwrap_or(owner);
    if hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        if hex.len() == 40 {
            return Some(checksum_diagnostic(owner));
        }
        if digits.is_some() {
            return None;
        }
    }
    if !owner.split('.').all(valid_wallet_label) {
        return None;
    }
    if owner.contains('.') {
        let literal = crate::browser_prompt::quoted_string(owner);
        return Some(format!(
            "when sending a str, it must be a hex string. Got: {literal}"
        ));
    }
    Some(format!("ENS name: '{owner}' is invalid."))
}

fn valid_wallet_label(label: &str) -> bool {
    use ens_normalize_rs::{DisallowedSequence, EnsNameNormalizer, ProcessError};

    static NORMALIZER: LazyLock<EnsNameNormalizer> = LazyLock::new(EnsNameNormalizer::default);
    // The provider strips emoji presentation selectors, but accepts nonempty labels
    // made entirely of other ignored code points.
    let label = label.replace('\u{fe0f}', "");
    if label.trim().is_empty() {
        return false;
    }
    matches!(
        NORMALIZER.process(label),
        Ok(_)
            | Err(ProcessError::DisallowedSequence(
                DisallowedSequence::EmptyLabel
            ))
    )
}

fn checksum_diagnostic(owner: &str) -> String {
    let message = if owner.bytes().any(|b| b.is_ascii_uppercase()) {
        "Address has an invalid EIP-55 checksum. After looking up the address from the original source, try again."
    } else {
        "web3.py only accepts checksum addresses. The software that gave you this non-checksum address should be considered unsafe, please file it as a bug on their platform. Try using an ENS name instead. Or, if you must accept lower safety, use Web3.to_checksum_address(lower_case_address)."
    };
    format!("('{message}', '{owner}')")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::post};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn wallet_labels_follow_the_provider_unicode_tables() {
        for label in ["病院", "bücher", "🦊", "\u{200b}", "a\u{fe0f}"] {
            assert!(valid_wallet_label(label), "{label:?}");
        }
        for label in ["", "a b", "раураl", "\u{fe0f}", "\u{1faea}"] {
            assert!(!valid_wallet_label(label), "{label:?}");
        }
    }

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
            signing_key: None,
            group: None,
            policy: None,
            timeout: Duration::from_secs(2),
        };
        let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
        assert!(
            matches!(chain.mint_retry("0x123","key").await,Err(PrepareError::Argument(s)) if s.contains("Argument 1 value `0x123` is not compatible"))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(
            matches!(chain.mint_retry(&format!("0x{}","ab".repeat(20)),"key").await,Err(PrepareError::Argument(s)) if s.contains("only accepts checksum addresses"))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        for owner in ["bad..eth", "a b.eth", ".eth"] {
            assert!(matches!(chain.mint_retry(owner, "key").await,
                Err(PrepareError::Argument(s)) if s.contains("Argument 1 value") && s.contains(owner)));
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        for (owner, detail) in [
            (
                "bücher.eth",
                "when sending a str, it must be a hex string. Got: 'bücher.eth'",
            ),
            (
                "a'b.eth",
                r#"when sending a str, it must be a hex string. Got: "a'b.eth""#,
            ),
            ("a-b", "ENS name: 'a-b' is invalid."),
        ] {
            assert!(matches!(chain.mint_retry(owner, "key").await,
                Err(PrepareError::Argument(s)) if s == detail));
        }
        assert_eq!(calls.load(Ordering::Relaxed), 4);
        server.abort();
    }
}
