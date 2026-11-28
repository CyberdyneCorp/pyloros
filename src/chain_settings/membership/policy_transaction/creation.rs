//! Resolve the directory identifier emitted by a confirmed contract creation.
use super::*;
use alloy_primitives::{Address, B256};

fn creation_data(receipt: &Value, contract: Address) -> Option<(Vec<u8>, B256)> {
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
    Some((bytes, block))
}

fn text_id(bytes: &[u8]) -> Option<TokenId> {
    let text = std::str::from_utf8(bytes).ok()?;
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    TokenId::from_str_radix(digits, 16)
        .ok()
        .filter(|_| !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_hexdigit()))
}

fn creation_ids(receipt: &Value, contract: Address) -> Option<(Vec<TokenId>, B256)> {
    let (bytes, block) = creation_data(receipt, contract)?;
    let mut ids = Vec::new();
    if bytes.len() == 32 {
        ids.push(TokenId::from_be_slice(&bytes));
    }
    if let Some(id) = text_id(&bytes) {
        ids.push(id);
    }
    (!ids.is_empty()).then_some((ids, block))
}

impl Chain {
    pub(crate) async fn create_role(
        &self,
        name: &str,
        description: Option<&str>,
        seconds: &str,
    ) -> Result<OperatorRole, PrepareError> {
        let duration = TokenId::from_str_radix(seconds, 10).map_err(|_| PrepareError::Invalid)?;
        let call = createRoleCall {
            name: name.into(),
            description: description.unwrap_or_default().into(),
            duration,
        };
        let envelope = self
            .prepare_envelope(self.policy.as_deref(), call.abi_encode())
            .await?;
        let contract = envelope.to;
        let receipt = self.submit_envelope(envelope).await?;
        let id = creation_data(&receipt, contract)
            .and_then(|(data, _)| text_id(&data))
            .ok_or_else(|| {
                eprintln!(
                    "Could not verify role ID for confirmed transaction {} on {contract}",
                    receipt["transactionHash"]
                );
                PrepareError::Invalid
            })?;
        Ok(OperatorRole {
            id: chain_uuid("role", id),
            name: name.into(),
            description: description.map(str::to_owned),
            chain_role_id: chain_number(id),
            max_session_duration_s: chain_number(duration),
            is_active: true,
            created_at: None,
        })
    }

    pub(crate) async fn create_policy(&self, body: &Value) -> Result<OperatorPolicy, PrepareError> {
        let tx = self
            .mutation_envelope(&IamMutation::CreatePolicy(body))
            .await?;
        let entry = self
            .create_directory_entry(
                tx,
                listPoliciesCall {},
                body["name"].as_str().ok_or(PrepareError::Invalid)?,
                body["description"].as_str(),
            )
            .await?;
        let mut response = OperatorPolicy::from(entry);
        response.description = body["description"].as_str().map(str::to_owned);
        response.statements = body["statements"]
            .as_array()
            .ok_or(PrepareError::Invalid)?
            .clone();
        Ok(response)
    }

    pub(crate) async fn create_group(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<OperatorGroup, PrepareError> {
        let tx = self.group_creation_envelope(name, description).await?;
        let entry = self
            .create_directory_entry(tx, listGroupsCall {}, name, description)
            .await?;
        Ok(OperatorGroup {
            id: chain_uuid("group", entry.id),
            name: entry.name,
            description: description.map(str::to_owned),
            is_active: true,
            member_count: 0,
            policy_ids: Vec::new(),
            chain_group_id: chain_number(entry.id),
            created_at: None,
        })
    }

    async fn create_directory_entry<C: SolCall<Return = Vec<CatalogEntry>> + Clone>(
        &self,
        tx: UnsignedIamTransaction,
        directory: C,
        name: &str,
        description: Option<&str>,
    ) -> Result<CatalogEntry, PrepareError> {
        let contract = tx.to;
        let address = contract.to_string();
        let prior = self
            .call(&address, directory.clone())
            .await
            .map_err(rpc_failure)?;
        let receipt = self.submit_envelope(tx).await?;
        self.created_entry(contract, directory, &prior, &receipt, name, description)
            .await
            .inspect_err(|_| {
                eprintln!(
                    "Could not verify directory ID for confirmed transaction {} on {contract}",
                    receipt["transactionHash"]
                );
            })
    }

    async fn created_entry<C: SolCall<Return = Vec<CatalogEntry>>>(
        &self,
        contract: Address,
        directory: C,
        prior: &[CatalogEntry],
        receipt: &Value,
        name: &str,
        description: Option<&str>,
    ) -> Result<CatalogEntry, PrepareError> {
        let (mut ids, block) = creation_ids(receipt, contract).ok_or(PrepareError::Invalid)?;
        ids.retain(|id| !prior.iter().any(|entry| entry.id == *id));
        if ids.is_empty() {
            return Err(PrepareError::Invalid);
        }
        let entries = self
            .call_at(
                &contract.to_string(),
                directory,
                json!({"blockHash":block,"requireCanonical":true}),
            )
            .await
            .map_err(rpc_failure)?;
        let mut matching = entries.into_iter().filter(|entry| {
            ids.contains(&entry.id)
                && entry.name == name
                && entry.description == description.unwrap_or_default()
        });
        let entry = matching.next().ok_or(PrepareError::Invalid)?;
        if matching.next().is_some() {
            return Err(PrepareError::Invalid);
        }
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn textual_role_ids_preserve_all_digits_and_reject_binary_words() {
        assert_eq!(text_id(b"0x42"), Some(TokenId::from(66)));
        assert_eq!(text_id(&[b'f'; 64]), Some(TokenId::MAX));
        assert_eq!(text_id(&[0xff; 32]), None);
        assert_eq!(text_id(b"0x"), None);
    }

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
