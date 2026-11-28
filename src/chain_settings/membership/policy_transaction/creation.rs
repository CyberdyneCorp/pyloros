//! Resolve the directory identifier emitted by a confirmed contract creation.
use super::*;
use alloy_primitives::{Address, B256};

fn creation_log(receipt: &Value, contract: Address) -> Option<(&Value, B256)> {
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
    Some((log, block))
}

fn creation_data(receipt: &Value, contract: Address) -> Option<(Vec<u8>, B256)> {
    let (log, block) = creation_log(receipt, contract)?;
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

pub(super) fn mint_id(receipt: &Value, contract: Address) -> Result<Option<TokenId>, PrepareError> {
    let logs = receipt["logs"].as_array().ok_or(PrepareError::Invalid)?;
    if logs.is_empty() {
        return Ok(None);
    }
    let (log, _) = creation_log(receipt, contract).ok_or(PrepareError::Invalid)?;
    let Some(data) = log.get("data") else {
        return Ok(Some(TokenId::ZERO));
    };
    let raw = data
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or(PrepareError::Invalid)?;
    let bytes = HEXLOWER_PERMISSIVE
        .decode(raw.as_bytes())
        .map_err(|_| PrepareError::Invalid)?;
    mint_text_integer(&bytes)
        .map(Some)
        .ok_or_else(|| invalid_mint_id(&bytes))
}

fn role_id(receipt: &Value, contract: Address) -> Option<TokenId> {
    creation_data(receipt, contract).and_then(|(data, _)| text_id(&data))
}

#[derive(serde::Serialize)]
pub struct CreationObservation {
    pub outcome: &'static str,
    pub candidate_ids: Vec<String>,
}

pub fn inspect_creation(
    kind: &str,
    hash: B256,
    contract: Address,
    receipt: &Value,
) -> Result<CreationObservation, &'static str> {
    if !matches!(kind, "group" | "policy" | "identity" | "role") {
        return Err("expected identity, group, policy or role");
    }
    let mut outcome = super::super::receipt::outcome(hash, Some(contract), receipt);
    let mut candidates = Vec::new();
    if outcome == "reported_success" {
        candidates = match kind {
            "identity" => mint_id(receipt, contract)
                .ok()
                .flatten()
                .into_iter()
                .collect(),
            "role" => role_id(receipt, contract).into_iter().collect(),
            _ => creation_ids(receipt, contract)
                .map(|(ids, _)| ids)
                .unwrap_or_default(),
        };
        candidates.dedup();
        outcome = if candidates.is_empty() {
            "no_matching_identifier"
        } else if kind == "identity" && receipt["logs"][0].get("data").is_none() {
            "missing_data_zero_fallback"
        } else {
            "decoded_candidates"
        };
    }
    Ok(CreationObservation {
        outcome,
        candidate_ids: candidates.into_iter().map(|id| id.to_string()).collect(),
    })
}

fn mint_text_integer(bytes: &[u8]) -> Option<TokenId> {
    // The provider parses the log bytes as a base-16 integer, including digit separators.
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if !bytes.is_ascii() {
        return None;
    }
    let digits = crate::unicode_decimal::hexadecimal_magnitude(text)?;
    let value = TokenId::from_str_radix(&digits, 16).ok()?;
    (!text.starts_with('-') || value.is_zero()).then_some(value)
}

fn invalid_mint_id(bytes: &[u8]) -> PrepareError {
    use std::fmt::Write;
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut literal = format!("b{}", char::from(quote));
    for &byte in bytes {
        if literal.len() >= 200 {
            break;
        }
        match byte {
            b'\n' => literal.push_str(r"\n"),
            b'\r' => literal.push_str(r"\r"),
            b'\t' => literal.push_str(r"\t"),
            b'\\' => literal.push_str(r"\\"),
            c if c == quote => {
                literal.push('\\');
                literal.push(char::from(c));
            }
            32..=126 => literal.push(char::from(byte)),
            _ => write!(literal, "\\x{byte:02x}").expect("write to string"),
        }
    }
    literal.push(char::from(quote));
    literal.truncate(200);
    PrepareError::Argument(format!("invalid literal for int() with base 16: {literal}"))
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
        let id = role_id(&receipt, contract).ok_or_else(|| {
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
        let entry = self.create_group_entry(name, description).await?;
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

    pub(crate) async fn create_group_entry(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<CatalogEntry, PrepareError> {
        let tx = self.group_creation_envelope(name, description).await?;
        self.create_directory_entry(tx, listGroupsCall {}, name, description)
            .await
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
    fn confirmed_mint_keeps_an_absent_id_distinct_from_zero() {
        let contract = Address::repeat_byte(4);
        let block = B256::repeat_byte(5);
        let hash = B256::repeat_byte(6);
        let mut receipt = json!({"blockHash":block,"transactionHash":hash,"logs":[]});
        assert!(matches!(mint_id(&receipt, contract), Ok(None)));
        receipt["logs"] = json!([{"blockHash":block,"transactionHash":hash,"address":contract}]);
        assert!(matches!(mint_id(&receipt,contract),Ok(Some(id)) if id==TokenId::ZERO));
        receipt["logs"][0]["data"] = json!(format!("0x{}", "66".repeat(64)));
        assert!(matches!(mint_id(&receipt,contract),Ok(Some(id)) if id==TokenId::MAX));
        receipt["logs"][0]["data"] = json!("0x");
        assert!(
            matches!(mint_id(&receipt,contract),Err(PrepareError::Argument(s)) if s.ends_with("b''"))
        );
        assert!(matches!(
            mint_id(&receipt, Address::ZERO),
            Err(PrepareError::Invalid)
        ));
    }

    #[test]
    fn mint_receipt_text_accepts_grouped_digits_without_losing_uint256_precision() {
        for (text, id) in [
            (b"+0x_FF".as_slice(), 255),
            (b"1_0", 16),
            (b"-0", 0),
            (b"\x0b0f\x0b", 15),
        ] {
            assert_eq!(mint_text_integer(text), Some(TokenId::from(id)));
        }
        let max = ["ffff"; 16].join("_");
        assert_eq!(mint_text_integer(max.as_bytes()), Some(TokenId::MAX));
        for invalid in [
            "0__1",
            "_ab",
            "ff_",
            "0x_",
            "-1",
            "1 0",
            "++1",
            &format!("1{max}"),
        ] {
            assert_eq!(mint_text_integer(invalid.as_bytes()), None);
        }
    }

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
