//! Submit exactly one envelope and reconcile the node's result with the local hash.
use super::*;
use alloy_primitives::{B256, keccak256};
use alloy_rlp::Encodable;
use k256::ecdsa::SigningKey;

static SUBMISSION_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()
        .expect("transaction submission client")
});

impl UnsignedIamTransaction {
    fn signed(&self, key: &k256::SecretKey) -> Result<Vec<u8>, PrepareError> {
        let digest = keccak256(self.signing_payload());
        let (signature, recovery) = SigningKey::from(key)
            .sign_prehash_recoverable(digest.as_slice())
            .map_err(|_| PrepareError::Invalid)?;
        if recovery.is_x_reduced() {
            return Err(PrepareError::Invalid);
        }
        Ok(self.signed_envelope(
            recovery.is_y_odd(),
            TokenId::from_be_bytes::<32>(signature.r().to_bytes().into()),
            TokenId::from_be_bytes::<32>(signature.s().to_bytes().into()),
        ))
    }

    fn signed_envelope(&self, odd: bool, r: TokenId, s: TokenId) -> Vec<u8> {
        let mut fields = self.encoded_fields();
        u8::from(odd).encode(&mut fields);
        r.encode(&mut fields);
        s.encode(&mut fields);
        Self::envelope(&fields)
    }
}

fn should_check_receipt(reply: Result<Value, ReadError>, expected: B256) -> bool {
    match reply {
        Ok(value) => value.as_str().and_then(|s| s.parse::<B256>().ok()) == Some(expected),
        Err(ReadError::Transport(_)) => true,
        Err(_) => false,
    }
}

enum Execution {
    Confirmed { hash: B256, receipt: Value },
    Reverted(B256),
    ReceiptTimeout,
}

impl Execution {
    // The token API uses an empty provider error when its receipt deadline expires.
    fn token_status_hash(self) -> Result<Option<String>, PrepareError> {
        match self {
            Self::Confirmed { hash, .. } => Ok(Some(HEXLOWER.encode(hash.as_slice()))),
            Self::Reverted(hash) => Err(PrepareError::Reverted(format!(
                "transaction reverted (tx={})",
                HEXLOWER.encode(hash.as_slice())
            ))),
            Self::ReceiptTimeout => Ok(None),
        }
    }
}

impl Chain {
    pub(crate) async fn submit_mutation(
        &self,
        mutation: &IamMutation<'_>,
    ) -> Result<(), PrepareError> {
        let tx = self.mutation_envelope(mutation).await?;
        self.submit_envelope(tx).await.map(|_| ())
    }

    pub(super) async fn submit_envelope(
        &self,
        tx: UnsignedIamTransaction,
    ) -> Result<Value, PrepareError> {
        match self.execute_envelope(tx).await? {
            Execution::Confirmed { receipt, .. } => Ok(receipt),
            Execution::ReceiptTimeout => Err(PrepareError::Unavailable),
            Execution::Reverted(hash) => Err(PrepareError::Reverted(format!(
                "transaction reverted (tx={hash})"
            ))),
        }
    }

    pub(super) async fn submit_token_status(
        &self,
        tx: UnsignedIamTransaction,
    ) -> Result<Option<String>, PrepareError> {
        self.execute_envelope(tx).await?.token_status_hash()
    }

    async fn execute_envelope(
        &self,
        tx: UnsignedIamTransaction,
    ) -> Result<Execution, PrepareError> {
        let signed = tx.signed(self.signing_key.as_ref().ok_or(PrepareError::Invalid)?)?;
        let expected = keccak256(&signed);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction",
                          "params":[format!("0x{}", HEXLOWER.encode(&signed))]});
        let reply = self
            .request(&SUBMISSION_CLIENT, &body.to_string(), RpcRead::Contract)
            .await;
        if let Err(ReadError::Rpc(error)) = reply {
            return Err(PrepareError::Rpc(error.diagnostic));
        }
        if !should_check_receipt(reply, expected) {
            return Err(PrepareError::Unavailable);
        }
        match self
            .wait_for_receipt(expected, Some(tx.to), Duration::from_secs(60))
            .await
        {
            Ok(("reported_success", receipt)) => Ok(Execution::Confirmed {
                hash: expected,
                receipt,
            }),
            Ok(("reported_revert", _)) => Ok(Execution::Reverted(expected)),
            Ok(("receipt_timeout", _)) => {
                eprintln!(
                    "Receipt deadline expired for IAM transaction {expected} on {}",
                    tx.to
                );
                Ok(Execution::ReceiptTimeout)
            }
            Err(error) => {
                eprintln!(
                    "Could not read receipt for IAM transaction {expected} on {}",
                    tx.to
                );
                Err(rpc_failure(error))
            }
            _ => {
                eprintln!(
                    "Unconfirmed IAM transaction {expected} for contract {}",
                    tx.to
                );
                Err(PrepareError::Unavailable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_status_uses_provider_hashes_and_preserves_a_missing_receipt() {
        let hash = B256::repeat_byte(0xab);
        let digits = "ab".repeat(32);
        assert!(
            matches!(Execution::Confirmed { hash, receipt: Value::Null }.token_status_hash(), Ok(Some(value)) if value==digits)
        );
        assert!(
            matches!(Execution::Reverted(hash).token_status_hash(),Err(PrepareError::Reverted(value)) if value==format!("transaction reverted (tx={digits})"))
        );
        assert!(matches!(
            Execution::ReceiptTimeout.token_status_hash(),
            Ok(None)
        ));
    }

    #[test]
    fn lost_submission_response_requires_reconciliation_by_local_hash() {
        let hash = B256::repeat_byte(1);
        assert!(should_check_receipt(Err(ReadError::Transport(None)), hash));
        assert!(should_check_receipt(Ok(json!(hash)), hash));
        assert!(!should_check_receipt(Ok(json!(B256::ZERO)), hash));
        assert!(!should_check_receipt(Ok(Value::Null), hash));
        assert!(!should_check_receipt(Err(ReadError::Failure), hash));
    }

    #[test]
    fn signed_membership_envelope_matches_mined_transaction() {
        let tx = UnsignedIamTransaction {
            to: "0x6FF819f11aE9aab60538DEB231726269fD695B47".parse().unwrap(),
            nonce: TokenId::from(3),
            data: HEXLOWER.decode(b"1783efc300000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000009").unwrap(),
            chain_id: TokenId::from(31337),
            gas: TokenId::from(68510),
            max_priority_fee_per_gas: TokenId::from(1_000_000_000u64),
            max_fee_per_gas: TokenId::from(2_541_679_034u64),
        };
        let r = "0xe51e607c5c07fb35ff5fa0c4c7075f39b4ad96aa93814e3f8939c40c5e91bbc4"
            .parse()
            .unwrap();
        let s = "0x0e52c7f8c0216c9bf70d93c986d04549f3e7b4c88830f877f801eabfb39944c8"
            .parse()
            .unwrap();
        let expected: B256 = "0xae7fe424a7b63e7d6e270023317cbd48afd463e2c870f1791b34c5cf57bfbe1e"
            .parse()
            .unwrap();
        assert_eq!(keccak256(tx.signed_envelope(false, r, s)), expected);
    }
}
