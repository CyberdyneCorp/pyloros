//! Resolve the policy identifier emitted by a confirmed contract creation.
use super::*;
use alloy_primitives::{Address, B256};

fn creation_ids(receipt: &Value, contract: Address) -> Option<(Vec<TokenId>, B256)> {
    let block: B256 = receipt["blockHash"].as_str()?.parse().ok()?;
    let tx: B256 = receipt["transactionHash"].as_str()?.parse().ok()?;
    let log = receipt["logs"].as_array()?.first()?;
    if log["address"].as_str()?.parse::<Address>().ok()? != contract
        || log["transactionHash"].as_str()?.parse::<B256>().ok()? != tx
        || log["blockHash"].as_str()?.parse::<B256>().ok()? != block
        || log
            .get("removed")
            .is_some_and(|flag| flag.as_bool() != Some(false))
    {
        return None;
    }
    let word = log["data"].as_str()?.strip_prefix("0x")?;
    if word.len() > 132 {
        return None;
    }
    let bytes = HEXLOWER_PERMISSIVE.decode(word.as_bytes()).ok()?;
    let mut ids = Vec::new();
    if bytes.len() == 32 {
        ids.push(TokenId::from_be_slice(&bytes));
    }
    if let Ok(text) = std::str::from_utf8(&bytes) {
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text);
        if !digits.is_empty()
            && digits.bytes().all(|digit| digit.is_ascii_hexdigit())
            && let Ok(id) = TokenId::from_str_radix(digits, 16)
        {
            ids.push(id);
        }
    }
    (!ids.is_empty()).then_some((ids, block))
}

impl Chain {
    pub(crate) async fn create_policy(&self, body: &Value) -> Result<OperatorPolicy, PrepareError> {
        let tx = self
            .mutation_envelope(&IamMutation::CreatePolicy(body))
            .await?;
        let contract = tx.to;
        let address = contract.to_string();
        let prior = self
            .call(&address, listPoliciesCall {})
            .await
            .map_err(rpc_failure)?;
        let receipt = self.submit_envelope(tx).await?;
        self.created_policy(contract, &prior, &receipt, body)
            .await
            .inspect_err(|_| {
                eprintln!(
                    "Could not verify policy ID for confirmed transaction {} on {contract}",
                    receipt["transactionHash"]
                );
            })
    }

    async fn created_policy(
        &self,
        contract: Address,
        prior: &[CatalogEntry],
        receipt: &Value,
        body: &Value,
    ) -> Result<OperatorPolicy, PrepareError> {
        let (mut ids, block) = creation_ids(receipt, contract).ok_or(PrepareError::Invalid)?;
        ids.retain(|id| !prior.iter().any(|entry| entry.id == *id));
        if ids.is_empty() {
            return Err(PrepareError::Invalid);
        }
        let entries = self
            .call_at(
                &contract.to_string(),
                listPoliciesCall {},
                json!({"blockHash":block,"requireCanonical":true}),
            )
            .await
            .map_err(rpc_failure)?;
        let mut matching = entries.into_iter().filter(|entry| {
            ids.contains(&entry.id)
                && Some(entry.name.as_str()) == body["name"].as_str()
                && entry.description == body["description"].as_str().unwrap_or_default()
        });
        let entry = matching.next().ok_or(PrepareError::Invalid)?;
        if matching.next().is_some() {
            return Err(PrepareError::Invalid);
        }
        let mut response = OperatorPolicy::from(entry);
        response.description = body["description"].as_str().map(str::to_owned);
        response.statements = body["statements"]
            .as_array()
            .ok_or(PrepareError::Invalid)?
            .clone();
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_full_width_id_only_from_the_recorded_transaction_and_contract() {
        let contract = Address::repeat_byte(4);
        let block = B256::repeat_byte(5);
        let hash = B256::repeat_byte(6);
        let mut receipt = json!({"blockHash":block,"transactionHash":hash,"logs":[{"address":contract,
            "transactionHash":hash,"blockHash":block,"data":format!("0x{}","ff".repeat(32)),"removed":false}]});
        assert_eq!(
            creation_ids(&receipt, contract),
            Some((vec![TokenId::MAX], block))
        );
        for (key, bad) in [
            ("blockHash", json!(hash)),
            ("transactionHash", json!(block)),
            ("address", json!(Address::ZERO)),
            ("removed", json!(true)),
            ("data", json!("0x1")),
        ] {
            let mut other = receipt.clone();
            other["logs"][0][key] = bad;
            assert!(creation_ids(&other, contract).is_none());
        }
        receipt["logs"][0]["data"] = json!("0x30783432");
        assert_eq!(
            creation_ids(&receipt, contract),
            Some((vec![TokenId::from(66)], block))
        );
        receipt["logs"] = json!([]);
        assert!(creation_ids(&receipt, contract).is_none());
    }
}
