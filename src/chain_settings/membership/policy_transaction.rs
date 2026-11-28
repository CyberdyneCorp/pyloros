//! Encode IAM contract calls and prepare unsigned EIP-1559 transactions.
use super::*;
use serde::Deserialize;
mod arguments;
mod quantities;
mod revert;
pub(super) use quantities::QuantityResult;

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
    function attach(uint256 identityId,uint256 policyId);
    function detach(uint256 identityId,uint256 policyId);
    function setBoundary(uint256 identityId,uint256 policyId);
    function clearBoundary(uint256 identityId);
    function attachGroupPolicy(uint256 groupId,uint256 policyId);
    function detachGroupPolicy(uint256 groupId,uint256 policyId);
    function addMember(uint256 groupId,uint256 identityId);
    function removeMember(uint256 groupId,uint256 identityId);
    function deleteGroup(uint256 id);
    function setStatus(uint256 tokenId,uint8 status);
    function mint(address owner,string publicKey,string email,string metadataURI);
    function createRole(string name,string description,uint256 duration);
    function createGroup(string name,string description);
}

fn empty_if_null<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

pub(crate) enum IamMutation<'a> {
    Boundary {
        identity: Uuid,
        policy: Option<Uuid>,
    },
    CreatePolicy(&'a Value),
    ReplacePolicy(Uuid, &'a Value),
    DeletePolicy(Uuid),
    DeleteGroup(Uuid),
    GroupMember {
        group: Uuid,
        identity: u32,
        add: bool,
    },
    UserPolicy {
        identity: u32,
        policy: Uuid,
        attach: bool,
    },
    GroupPolicy {
        group: Uuid,
        policy: Uuid,
        attach: bool,
    },
}

pub(crate) enum PrepareError {
    MissingPolicy(Uuid),
    MissingIdentity(Uuid),
    MissingGroup(Uuid),
    ProtectedGroup,
    Catalog(SnapshotError),
    Reverted(String),
    Rpc(String),
    Argument(String),
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
            Self::Boundary { identity, policy } => {
                let snapshot = chain.snapshot().await.map_err(PrepareError::Catalog)?;
                let token = snapshot
                    .identities
                    .into_iter()
                    .find(|id| chain_uuid("identity", *id) == *identity)
                    .ok_or(PrepareError::MissingIdentity(*identity))?;
                match policy {
                    Some(id) => Ok(setBoundaryCall {
                        identityId: token,
                        policyId: chain.required_policy(*id).await?.id,
                    }
                    .abi_encode()),
                    None => Ok(clearBoundaryCall { identityId: token }.abi_encode()),
                }
            }
            Self::UserPolicy {
                identity,
                policy,
                attach,
            } => {
                let policy_id = chain.required_policy(*policy).await?.id;
                let identity_id = TokenId::from(*identity);
                Ok(if *attach {
                    attachCall {
                        identityId: identity_id,
                        policyId: policy_id,
                    }
                    .abi_encode()
                } else {
                    detachCall {
                        identityId: identity_id,
                        policyId: policy_id,
                    }
                    .abi_encode()
                })
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

struct UnsignedIamTransaction {
    to: alloy_primitives::Address,
    nonce: TokenId,
    data: Vec<u8>,
    chain_id: TokenId,
    gas: TokenId,
    max_priority_fee_per_gas: TokenId,
    max_fee_per_gas: TokenId,
}

impl UnsignedIamTransaction {
    fn signing_payload(&self) -> Vec<u8> {
        use alloy_rlp::Encodable;
        let mut fields = Vec::new();
        self.chain_id.encode(&mut fields);
        self.nonce.encode(&mut fields);
        self.max_priority_fee_per_gas.encode(&mut fields);
        self.max_fee_per_gas.encode(&mut fields);
        self.gas.encode(&mut fields);
        self.to.encode(&mut fields);
        TokenId::ZERO.encode(&mut fields);
        self.data.as_slice().encode(&mut fields);
        fields.push(alloy_rlp::EMPTY_LIST_CODE);
        let mut payload = vec![0x02];
        alloy_rlp::Header {
            list: true,
            payload_length: fields.len(),
        }
        .encode(&mut payload);
        payload.extend_from_slice(&fields);
        payload
    }
}

fn rpc_failure(error: ReadError) -> PrepareError {
    error
        .into_diagnostic()
        .map_or(PrepareError::Unavailable, PrepareError::Rpc)
}

fn quantity(value: &Value) -> Result<TokenId, PrepareError> {
    TokenId::deserialize(value).map_err(|_| PrepareError::Unavailable)
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

    async fn quantity_rpc(&self, method: &str, params: Value) -> Result<Value, ReadError> {
        self.rpc_bounded(
            method,
            params,
            RpcRead::TransactionQuantity(QuantityResult::Scalar),
        )
        .await
    }

    async fn quantity(&self, method: &str, params: Value) -> Result<TokenId, PrepareError> {
        quantity(
            &self
                .quantity_rpc(method, params)
                .await
                .map_err(rpc_failure)?,
        )
    }

    async fn priority_fee(&self) -> Result<TokenId, PrepareError> {
        match self
            .quantity_rpc("eth_maxPriorityFeePerGas", json!([]))
            .await
        {
            Ok(fee) => quantity(&fee),
            Err(ReadError::Rpc(..)) => {
                let history = self
                    .rpc_bounded(
                        "eth_feeHistory",
                        json!(["0xa", "pending", [5.0]]),
                        RpcRead::TransactionQuantity(QuantityResult::History),
                    )
                    .await
                    .map_err(rpc_failure)?;
                history_priority_fee(&history)
            }
            Err(error) => Err(rpc_failure(error)),
        }
    }

    pub(crate) async fn lock_signer(&self, tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<()> {
        let signer = self
            .signer
            .as_deref()
            .ok_or_else(|| sqlx::Error::Configuration("invalid chain signer".into()))?;
        // Endpoint aliases can refer to the same chain. Use the address across all
        // chain configurations sharing this database.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('iam-signer'), hashtext(lower($1)))")
            .bind(signer)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    pub(crate) async fn prepare_mutation(
        &self,
        mutation: &IamMutation<'_>,
    ) -> Result<Vec<u8>, PrepareError> {
        let call = mutation.calldata(self).await?;
        let address = match mutation {
            IamMutation::GroupMember { .. }
            | IamMutation::DeleteGroup(_)
            | IamMutation::GroupPolicy { .. } => self.group.as_deref(),
            _ => self.policy.as_deref(),
        };
        self.prepare_contract(address, call).await
    }

    pub(crate) async fn prepare_token_status(
        &self,
        token: &str,
        status: u8,
    ) -> Result<Vec<u8>, PrepareError> {
        let id = TokenId::from_str_radix(token, 10).map_err(|_| {
            arguments::incompatible_first(
                "setStatus",
                &["uint256", "uint8"],
                "int,int",
                &[token, &status.to_string()],
            )
        })?;
        self.prepare_contract(
            self.identity.as_deref(),
            setStatusCall {
                tokenId: id,
                status,
            }
            .abi_encode(),
        )
        .await
    }

    pub(crate) async fn prepare_identity_creation(
        &self,
        owner: &str,
        public_key: &str,
        metadata_uri: &str,
    ) -> Result<Vec<u8>, PrepareError> {
        validate_address(owner).map_err(|_| PrepareError::Invalid)?;
        let call = mintCall {
            owner: owner.parse().map_err(|_| PrepareError::Invalid)?,
            publicKey: public_key.into(),
            email: String::new(),
            metadataURI: metadata_uri.into(),
        };
        self.prepare_contract(self.identity.as_deref(), call.abi_encode())
            .await
    }

    pub(crate) async fn prepare_role_creation(
        &self,
        name: &str,
        description: Option<&str>,
        seconds: &str,
    ) -> Result<Vec<u8>, PrepareError> {
        let call = createRoleCall {
            name: name.into(),
            description: description.unwrap_or_default().into(),
            duration: TokenId::from_str_radix(seconds, 10).map_err(|_| PrepareError::Invalid)?,
        };
        self.prepare_contract(self.policy.as_deref(), call.abi_encode())
            .await
    }

    async fn require_role_group(&self, group_id: TokenId) -> Result<(), PrepareError> {
        let current = self.snapshot().await.map_err(PrepareError::Catalog)?;
        if !current.groups.iter().any(|group| group.id == group_id) {
            return Err(PrepareError::MissingGroup(chain_uuid("group", group_id)));
        }
        Ok(())
    }

    pub(crate) async fn prepare_role_membership(
        &self,
        group_id: TokenId,
        identity: i32,
        add: bool,
    ) -> Result<Vec<u8>, PrepareError> {
        self.require_role_group(group_id).await?;
        let identity_id = TokenId::from(
            u32::try_from(identity)
                .map_err(|_| PrepareError::Argument("invalid identity token".into()))?,
        );
        let call = if add {
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
        };
        self.prepare_contract(self.group.as_deref(), call).await
    }

    pub(crate) async fn prepare_role_group_removal(
        &self,
        group_id: TokenId,
    ) -> Result<Vec<u8>, PrepareError> {
        self.require_role_group(group_id).await?;
        self.prepare_contract(
            self.group.as_deref(),
            deleteGroupCall { id: group_id }.abi_encode(),
        )
        .await
    }

    pub(crate) async fn prepare_group_creation(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<Vec<u8>, PrepareError> {
        let call = createGroupCall {
            name: name.into(),
            description: description.unwrap_or_default().into(),
        };
        self.prepare_contract(self.group.as_deref(), call.abi_encode())
            .await
    }

    async fn prepare_contract(
        &self,
        address: Option<&str>,
        call: Vec<u8>,
    ) -> Result<Vec<u8>, PrepareError> {
        let to = address.ok_or(PrepareError::Unavailable)?;
        validate_address(to).map_err(|_| PrepareError::Unavailable)?;
        let from = self.signer.as_deref().ok_or(PrepareError::Invalid)?;
        let data = format!("0x{}", HEXLOWER.encode(&call));
        let nonce = self
            .quantity("eth_getTransactionCount", json!([from, "pending"]))
            .await?;
        let chain_id = self.quantity("eth_chainId", json!([])).await?;
        let estimate = self
            .quantity_rpc(
                "eth_estimateGas",
                json!([{"from":from,"nonce":format!("{nonce:#x}"),"to":to,"data":&data},"latest"]),
            )
            .await
            .map_err(revert::estimate_error)?;
        let gas = quantity(&estimate)?;
        let max_priority_fee_per_gas = self.priority_fee().await?;
        let block = self
            .rpc_bounded(
                "eth_getBlockByNumber",
                json!(["latest", false]),
                RpcRead::TransactionQuantity(QuantityResult::Block),
            )
            .await
            .map_err(rpc_failure)?;
        let base = quantity(&block)?;
        let max_fee_per_gas = base
            .checked_mul(TokenId::from(2))
            .and_then(|v| v.checked_add(max_priority_fee_per_gas))
            .ok_or(PrepareError::Unavailable)?;
        Ok(UnsignedIamTransaction {
            to: to.parse().map_err(|_| PrepareError::Invalid)?,
            nonce,
            data: call,
            chain_id,
            gas,
            max_priority_fee_per_gas,
            max_fee_per_gas,
        }
        .signing_payload())
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
    #[ignore = "requires PostgreSQL"]
    async fn signer_lock_spans_connections_and_releases_on_transaction_end() {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut first = Chain::for_health_test("http://first".into());
        first.signer = Some("0x00000000000000000000000000000000000000Ab".into());
        let mut alias = Chain::for_health_test("http://alias".into());
        alias.signer = first.signer.as_ref().map(|s| s.to_ascii_lowercase());
        let mut other = Chain::for_health_test("http://first".into());
        other.signer = Some("0x0000000000000000000000000000000000000001".into());
        for commit in [true, false] {
            let mut owner = pool.begin().await.unwrap();
            first.lock_signer(&mut owner).await.unwrap();
            let mut waiter = pool.begin().await.unwrap();
            other.lock_signer(&mut waiter).await.unwrap();
            let waiting = alias.lock_signer(&mut waiter);
            tokio::pin!(waiting);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut waiting)
                    .await
                    .is_err()
            );
            if commit {
                owner.commit().await.unwrap();
            } else {
                owner.rollback().await.unwrap();
            }
            tokio::time::timeout(Duration::from_secs(2), waiting)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn unsigned_payload_preserves_rlp_boundaries_and_full_width_quantities() {
        let mut tx = UnsignedIamTransaction {
            to: alloy_primitives::Address::ZERO,
            nonce: TokenId::ZERO,
            data: vec![],
            chain_id: TokenId::from(1),
            gas: TokenId::from(21000),
            max_priority_fee_per_gas: TokenId::from(1),
            max_fee_per_gas: TokenId::from(2),
        };
        assert_eq!(
            HEXLOWER.encode(&tx.signing_payload()),
            "02df018001028252089400000000000000000000000000000000000000008080c0"
        );
        for (size, nonce, expected) in [
            (
                55,
                TokenId::from(127),
                "bebec068cd563a84e3b6c6575199b22746778d736fbe2e40f797064853dab7ae",
            ),
            (
                56,
                TokenId::from(128),
                "bcf6a14ed09b26e77c069104b53b725442ad5ffe902aa9245c1b7b0143b97a05",
            ),
            (
                256,
                TokenId::MAX,
                "0d10952c25ee1f20d2ff19740eb77379b4730966900cb1e027f950af9eef2ee9",
            ),
        ] {
            tx.data = vec![0xa5; size];
            tx.nonce = nonce;
            assert_eq!(
                format!("{:x}", alloy_primitives::keccak256(tx.signing_payload())),
                expected
            );
        }
    }

    #[tokio::test]
    async fn prepares_a_zero_value_call_with_pending_nonce_and_history_based_fees() {
        const SIGNER: &str = "0x0000000000000000000000000000000000000001";
        const CONTRACT: &str = "0x0000000000000000000000000000000000000002";
        async fn rpc(Json(req): Json<Value>) -> Json<Value> {
            let result = match req["method"].as_str().unwrap() {
                "eth_getTransactionCount" => {
                    assert_eq!(req["params"], json!([SIGNER, "pending"]));
                    json!(17)
                }
                "eth_chainId" => json!("0X539"),
                "eth_estimateGas" => {
                    let data = req["params"][0]["data"].as_str().unwrap();
                    let bytes = HEXLOWER.decode(&data.as_bytes()[2..]).unwrap();
                    let call = createPolicyCall::abi_decode_validate(&bytes).unwrap();
                    assert_eq!(call.name, "tools");
                    assert_eq!(call.statements[0].conditions[0].comparison, "IpAddress");
                    assert_eq!(call.statements[0].sid, "");
                    assert_eq!(req["params"][0]["to"], CONTRACT);
                    assert_eq!(req["params"][0]["nonce"], "0x11");
                    json!("7791")
                }
                "eth_maxPriorityFeePerGas" => {
                    return Json(
                        json!({"id":1,"jsonrpc":"2.0","error":{"code":-32601,"message":"unsupported"}}),
                    );
                }
                "eth_feeHistory" => {
                    assert_eq!(req["params"], json!(["0xa", "pending", [5.0]]));
                    json!({"reward":[["0x0"],[1000000000],["0X3B9ACA00"]],"baseFeePerGas":[1,2,3,4]})
                }
                "eth_getBlockByNumber" => json!({"baseFeePerGas":21}),
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
        // Independent ABI and RLP encoding of the complete unsigned fixture.
        assert_eq!(tx.len(), 1171);
        assert_eq!(
            format!("{:x}", alloy_primitives::keccak256(&tx)),
            "6ec4655fff2e7eaa5a791cfff266bcd970dfcb97b6b696326b17f4d9b93c4d37"
        );
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
