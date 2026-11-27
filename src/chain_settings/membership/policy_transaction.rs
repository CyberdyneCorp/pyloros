//! Encode IAM contract calls and prepare unsigned EIP-1559 transactions.
use super::*;
use serde::Deserialize;
mod revert;

sol! {
    #[derive(Deserialize)]
    struct Clause {
        #[serde(rename="operator")]
        string comparison;
        string key;
        string value;
    }
    #[derive(Deserialize)]
    struct Rule {
        string effect;
        string[] actions;
        string[] resources;
        Clause[] conditions;
        #[serde(deserialize_with="empty_if_null")]
        string sid;
    }
    function createPolicy(string name,string description,Rule[] statements);
    function updatePolicy(uint256 id,string name,string description,Rule[] statements);
    function deletePolicy(uint256 id);
    function attachGroupPolicy(uint256 groupId,uint256 policyId);
    function detachGroupPolicy(uint256 groupId,uint256 policyId);
    function addMember(uint256 groupId,uint256 identityId);
    function removeMember(uint256 groupId,uint256 identityId);
    function deleteGroup(uint256 id);
    function createGroup(string name,string description);
}

fn empty_if_null<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

pub(crate) enum IamMutation<'a> {
    CreatePolicy(&'a Value),
    ReplacePolicy(Uuid, &'a Value),
    DeletePolicy(Uuid),
    DeleteGroup(Uuid),
    GroupMember {
        group: Uuid,
        identity: u32,
        add: bool,
    },
    GroupPolicy {
        group: Uuid,
        policy: Uuid,
        attach: bool,
    },
}

pub(crate) enum PrepareError {
    MissingPolicy(Uuid),
    MissingGroup(Uuid),
    ProtectedGroup,
    Catalog(SnapshotError),
    Reverted(String),
    Unavailable,
    Invalid,
}

struct PolicyFields {
    name: String,
    description: String,
    statements: Vec<Rule>,
}

impl PolicyFields {
    fn from_request(body: &Value, prior: Option<&CatalogEntry>) -> Result<Self, PrepareError> {
        let name = body["name"]
            .as_str()
            .or_else(|| prior.map(|p| p.name.as_str()))
            .ok_or(PrepareError::Invalid)?
            .to_owned();
        let description = body["description"]
            .as_str()
            .or_else(|| prior.map(|p| p.description.as_str()))
            .unwrap_or_default()
            .to_owned();
        let statements =
            Vec::<Rule>::deserialize(&body["statements"]).map_err(|_| PrepareError::Invalid)?;
        Ok(Self {
            name,
            description,
            statements,
        })
    }
}

impl IamMutation<'_> {
    async fn calldata(&self, chain: &Chain) -> Result<Vec<u8>, PrepareError> {
        match self {
            Self::CreatePolicy(body) => {
                let PolicyFields {
                    name,
                    description,
                    statements,
                } = PolicyFields::from_request(body, None)?;
                Ok(createPolicyCall {
                    name,
                    description,
                    statements,
                }
                .abi_encode())
            }
            Self::ReplacePolicy(id, body) => {
                let target = chain.required_policy(*id).await?.id;
                // Re-read metadata immediately before encoding a replacement.
                let prior = chain
                    .policy_entry(*id)
                    .await
                    .map_err(PrepareError::Catalog)?
                    .ok_or(PrepareError::Invalid)?;
                let PolicyFields {
                    name,
                    description,
                    statements,
                } = PolicyFields::from_request(body, Some(&prior))?;
                Ok(updatePolicyCall {
                    id: target,
                    name,
                    description,
                    statements,
                }
                .abi_encode())
            }
            Self::GroupPolicy {
                group,
                policy,
                attach,
            } => {
                let group_id = chain
                    .group_entry(*group)
                    .await?
                    .ok_or(PrepareError::MissingGroup(*group))?
                    .id;
                let policy_id = chain.required_policy(*policy).await?.id;
                Ok(if *attach {
                    attachGroupPolicyCall {
                        groupId: group_id,
                        policyId: policy_id,
                    }
                    .abi_encode()
                } else {
                    detachGroupPolicyCall {
                        groupId: group_id,
                        policyId: policy_id,
                    }
                    .abi_encode()
                })
            }
            Self::GroupMember {
                group,
                identity,
                add,
            } => {
                let group_id = chain
                    .ordinary_group(*group)
                    .await?
                    .ok_or(PrepareError::MissingGroup(*group))?
                    .id;
                let identity_id = TokenId::from(*identity);
                Ok(if *add {
                    addMemberCall {
                        groupId: group_id,
                        identityId: identity_id,
                    }
                    .abi_encode()
                } else {
                    removeMemberCall {
                        groupId: group_id,
                        identityId: identity_id,
                    }
                    .abi_encode()
                })
            }
            Self::DeleteGroup(id) => {
                // Group deletion checks namespace ownership and then resolves the current chain ID.
                chain.ordinary_group(*id).await?;
                let group = chain
                    .ordinary_group(*id)
                    .await?
                    .ok_or(PrepareError::MissingGroup(*id))?;
                Ok(deleteGroupCall { id: group.id }.abi_encode())
            }
            Self::DeletePolicy(id) => Ok(deletePolicyCall {
                id: chain.required_policy(*id).await?.id,
            }
            .abi_encode()),
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnsignedIamTransaction<'a> {
    from: &'a str,
    to: &'a str,
    nonce: TokenId,
    data: String,
    chain_id: TokenId,
    gas: TokenId,
    max_priority_fee_per_gas: TokenId,
    max_fee_per_gas: TokenId,
    value: TokenId,
}

fn quantity(value: &Value) -> Result<TokenId, PrepareError> {
    let hex = value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .filter(|s| !s.is_empty())
        .ok_or(PrepareError::Unavailable)?;
    TokenId::from_str_radix(hex, 16).map_err(|_| PrepareError::Unavailable)
}

impl Chain {
    async fn group_entry(&self, id: Uuid) -> Result<Option<Group>, PrepareError> {
        Ok(self
            .snapshot()
            .await
            .map_err(PrepareError::Catalog)?
            .groups
            .into_iter()
            .find(|g| chain_uuid("group", g.id) == id))
    }
    pub(crate) async fn check_group_namespace(&self, id: Uuid) -> Result<(), PrepareError> {
        self.ordinary_group(id).await.map(|_| ())
    }
    async fn ordinary_group(&self, id: Uuid) -> Result<Option<Group>, PrepareError> {
        let group = self.group_entry(id).await?;
        if group.as_ref().is_some_and(|g| g.name.starts_with("rp:")) {
            return Err(PrepareError::ProtectedGroup);
        }
        Ok(group)
    }
    async fn required_policy(&self, id: Uuid) -> Result<CatalogEntry, PrepareError> {
        self.policy_entry(id)
            .await
            .map_err(PrepareError::Catalog)?
            .ok_or(PrepareError::MissingPolicy(id))
    }

    async fn quantity(&self, method: &str, params: Value) -> Result<TokenId, PrepareError> {
        quantity(
            &self
                .rpc(method, params)
                .await
                .map_err(|_| PrepareError::Unavailable)?,
        )
    }

    async fn priority_fee(&self) -> Result<TokenId, PrepareError> {
        match self.rpc("eth_maxPriorityFeePerGas", json!([])).await {
            Ok(fee) => quantity(&fee),
            Err(ReadError::Rpc(..)) => {
                let history = self
                    .rpc("eth_feeHistory", json!(["0xa", "pending", [5.0]]))
                    .await
                    .map_err(|_| PrepareError::Unavailable)?;
                history_priority_fee(&history)
            }
            Err(_) => Err(PrepareError::Unavailable),
        }
    }

    pub(crate) async fn prepare_mutation(
        &self,
        mutation: &IamMutation<'_>,
    ) -> Result<UnsignedIamTransaction<'_>, PrepareError> {
        let call = mutation.calldata(self).await?;
        let address = match mutation {
            IamMutation::GroupMember { .. }
            | IamMutation::DeleteGroup(_)
            | IamMutation::GroupPolicy { .. } => self.group.as_deref(),
            _ => self.policy.as_deref(),
        };
        self.prepare_contract(address, call).await
    }

    pub(crate) async fn prepare_group_creation(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<UnsignedIamTransaction<'_>, PrepareError> {
        let call = createGroupCall {
            name: name.into(),
            description: description.unwrap_or_default().into(),
        };
        self.prepare_contract(self.group.as_deref(), call.abi_encode())
            .await
    }

    async fn prepare_contract<'a>(
        &'a self,
        address: Option<&'a str>,
        call: Vec<u8>,
    ) -> Result<UnsignedIamTransaction<'a>, PrepareError> {
        let to = address.ok_or(PrepareError::Unavailable)?;
        validate_address(to).map_err(|_| PrepareError::Unavailable)?;
        let from = self.signer.as_deref().ok_or(PrepareError::Invalid)?;
        let data = format!("0x{}", HEXLOWER.encode(&call));
        let nonce = self
            .quantity("eth_getTransactionCount", json!([from, "pending"]))
            .await?;
        let chain_id = self.quantity("eth_chainId", json!([])).await?;
        let estimate = self
            .rpc(
                "eth_estimateGas",
                json!([{"from":from,"nonce":format!("{nonce:#x}"),"to":to,"data":&data},"latest"]),
            )
            .await
            .map_err(revert::estimate_error)?;
        let gas = quantity(&estimate)?;
        let max_priority_fee_per_gas = self.priority_fee().await?;
        let block = self
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await
            .map_err(|_| PrepareError::Unavailable)?;
        let base = quantity(&block["baseFeePerGas"])?;
        let max_fee_per_gas = base
            .checked_mul(TokenId::from(2))
            .and_then(|v| v.checked_add(max_priority_fee_per_gas))
            .ok_or(PrepareError::Unavailable)?;
        Ok(UnsignedIamTransaction {
            from,
            to,
            nonce,
            data,
            chain_id,
            gas,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            value: TokenId::ZERO,
        })
    }
}

fn history_priority_fee(history: &Value) -> Result<TokenId, PrepareError> {
    let rows = history["reward"]
        .as_array()
        .ok_or(PrepareError::Unavailable)?;
    let mut count = 0u64;
    let mut sum = TokenId::ZERO;
    for row in rows {
        let fee = quantity(&row[0])?;
        if fee != TokenId::ZERO {
            sum = sum.saturating_add(fee);
            count += 1;
        }
    }
    let count = count.max(1);
    let cap = TokenId::from(count) * TokenId::from(1_500_000_000u64);
    let mean = sum.min(cap).to::<u64>() as f64 / count as f64;
    Ok(TokenId::from(
        (mean.round_ties_even() as u64).clamp(1_000_000_000, 1_500_000_000),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::post};

    #[tokio::test]
    async fn prepares_a_zero_value_call_with_pending_nonce_and_history_based_fees() {
        const SIGNER: &str = "0x0000000000000000000000000000000000000001";
        const CONTRACT: &str = "0x0000000000000000000000000000000000000002";
        async fn rpc(Json(req): Json<Value>) -> Json<Value> {
            let result = match req["method"].as_str().unwrap() {
                "eth_getTransactionCount" => {
                    assert_eq!(req["params"], json!([SIGNER, "pending"]));
                    json!("0x11")
                }
                "eth_chainId" => json!("0x539"),
                "eth_estimateGas" => {
                    let data = req["params"][0]["data"].as_str().unwrap();
                    let bytes = HEXLOWER.decode(&data.as_bytes()[2..]).unwrap();
                    let call = createPolicyCall::abi_decode_validate(&bytes).unwrap();
                    assert_eq!(call.name, "tools");
                    assert_eq!(call.statements[0].conditions[0].comparison, "IpAddress");
                    assert_eq!(call.statements[0].sid, "");
                    assert_eq!(req["params"][0]["to"], CONTRACT);
                    assert_eq!(req["params"][0]["nonce"], "0x11");
                    json!("0x7791")
                }
                "eth_maxPriorityFeePerGas" => {
                    return Json(
                        json!({"id":1,"jsonrpc":"2.0","error":{"code":-32601,"message":"unsupported"}}),
                    );
                }
                "eth_feeHistory" => {
                    assert_eq!(req["params"], json!(["0xa", "pending", [5.0]]));
                    json!({"reward":[["0x0"]]})
                }
                "eth_getBlockByNumber" => json!({"baseFeePerGas":"0x15"}),
                _ => panic!("unexpected RPC"),
            };
            Json(json!({"id":1,"jsonrpc":"2.0","result":result}))
        }
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let chain = Chain {
            identity: None,
            endpoint: format!("http://{}", socket.local_addr().unwrap()),
            signer: Some(SIGNER.into()),
            policy: Some(CONTRACT.into()),
            group: None,
            timeout: Duration::from_secs(2),
        };
        let server = tokio::spawn(async move {
            axum::serve(socket, Router::new().route("/", post(rpc)))
                .await
                .unwrap()
        });
        let doc = json!({"name":"tools","description":null,"statements":[{"effect":"allow","actions":["use"],"resources":["tool"],"conditions":[{"operator":"IpAddress","key":"network","value":"local"}],"sid":null}]});
        let tx = chain
            .prepare_mutation(&IamMutation::CreatePolicy(&doc))
            .await
            .ok()
            .unwrap();
        assert_eq!(tx.nonce, TokenId::from(17));
        assert_eq!(tx.chain_id, TokenId::from(1337));
        assert_eq!(tx.gas, TokenId::from(0x7791));
        assert_eq!(tx.max_fee_per_gas, TokenId::from(1_000_000_042));
        assert_eq!(tx.value, TokenId::ZERO);
        server.abort();
    }

    #[test]
    fn history_ignores_empty_blocks_and_rounds_halfway_fees_to_even() {
        let history = json!({"reward":[["0x0"],["0x3b9aca01"],["0x3b9aca02"]]});
        assert_eq!(
            history_priority_fee(&history).ok(),
            Some(TokenId::from(1_000_000_002))
        );
        assert!(quantity(&json!(format!("0x1{}", "0".repeat(64)))).is_err());
    }
}
