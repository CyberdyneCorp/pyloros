//! Read the membership of one identity at a specific canonical block.
use super::{Chain, TokenId, getMembersCall};
use alloy_primitives::{Address, B256};
use serde::Serialize;
use serde_json::json;
use std::error::Error;

pub(super) fn inspection_chain() -> Result<Chain, Box<dyn Error>> {
    Ok(Chain {
        endpoint: std::env::var("BLOCKCHAIN_RPC_ENDPOINT")?,
        identity: None,
        policy: None,
        group: None,
        signer: None,
        signing_key: None,
        timeout: super::super::rpc_timeout()?,
    })
}

#[derive(Serialize)]
pub struct MembershipObservation {
    contract: String,
    block_hash: B256,
    group_id: String,
    identity_token_id: String,
    member: bool,
}

fn decimal_id(raw: &str) -> Result<TokenId, Box<dyn Error>> {
    if raw.is_empty() || !raw.bytes().all(|digit| digit.is_ascii_digit()) {
        return Err("expected an unsigned decimal token or group ID".into());
    }
    TokenId::from_str_radix(raw, 10).map_err(|_| "decimal ID exceeds uint256 range".into())
}

pub async fn inspect_membership(
    contract: &str,
    group: &str,
    identity: &str,
    block: &str,
) -> Result<MembershipObservation, Box<dyn Error>> {
    let contract = contract.parse::<Address>()?.to_checksum(None);
    let block_hash = block.parse::<B256>()?;
    let group = decimal_id(group)?;
    let identity = decimal_id(identity)?;
    let members = inspection_chain()?
        .call_at(
            &contract,
            getMembersCall { groupId: group },
            json!({"blockHash":block_hash,"requireCanonical":true}),
        )
        .await
        .map_err(|_| "Could not read group members at the requested canonical block")?;
    Ok(MembershipObservation {
        contract,
        block_hash,
        group_id: group.to_string(),
        identity_token_id: identity.to_string(),
        member: members.contains(&identity),
    })
}
