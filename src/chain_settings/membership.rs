//! Read the authority's IAM inventory without sending transactions.
mod health_connection;
mod large_health;
pub(super) mod policy_transaction;
pub(super) mod receipt;
mod rpc_response;
mod transport;
use super::ChainSettings;
use alloy_sol_types::{SolCall, sol};
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::{Acquire, Postgres, Transaction};
use std::{sync::LazyLock, time::Duration};
use uuid::Uuid;

sol! {
    struct CatalogEntry {
        uint256 id;
        string name;
        string description;
        address creator;
        uint256 count;
        bool active;
        uint256 createdAt;
    }
    function identityOf(uint256 tokenId) external view returns (address owner,uint8 status,string publicKey,string email);
    function listPolicies() external view returns (CatalogEntry[]);
    function listGroups() external view returns (CatalogEntry[]);
    function getMembers(uint256 groupId) external view returns (uint256[]);
    function getGroupPolicies(uint256 groupId) external view returns (uint256[]);
}

static CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .no_gzip()
        .no_deflate()
        .build()
        .expect("TLS client")
});

#[derive(Clone)]
pub(crate) struct Chain {
    pub(super) endpoint: String,
    pub(super) identity: Option<String>,
    policy: Option<String>,
    group: Option<String>,
    signer: Option<String>,
    timeout: Duration,
}

impl ChainSettings {
    pub(crate) async fn provider(&self) -> Option<Chain> {
        self.membership_source()
            .await
            .or_else(|| self.deployment.clone())
    }

    pub(crate) async fn iam_source(&self) -> Result<Option<Chain>, sqlx::Error> {
        let runtime = self.membership_source().await;
        if let Some(provider) = runtime.as_ref().or(self.deployment.as_ref()) {
            provider.validate_signer()?;
        }
        Ok(runtime)
    }

    pub(crate) async fn membership_source(&self) -> Option<Chain> {
        let state = self.state.read().await;
        self.runtime_chain(&state)
    }

    pub(super) fn runtime_chain(&self, state: &super::Configuration) -> Option<Chain> {
        let view = state.view();
        view.is_configured.then(|| Chain {
            identity: view.identity_contract_address,
            endpoint: view.rpc_url.unwrap_or_default(),
            policy: view.policy_contract_address,
            group: view.group_contract_address,
            signer: view.signer_address,
            timeout: self.rpc_timeout.unwrap_or(Duration::from_secs(10)),
        })
    }
}

type TokenId = alloy_primitives::U256;

#[derive(Debug, Clone)]
pub(crate) struct Group {
    pub(crate) id: TokenId,
    pub(crate) policy_ids: Vec<TokenId>,
    pub(crate) name: String,
    pub(crate) description: String,
    members: Vec<TokenId>,
}

#[derive(serde::Serialize)]
pub(crate) struct OperatorGroup {
    id: Uuid,
    name: String,
    description: Option<String>,
    is_active: bool,
    member_count: usize,
    policy_ids: Vec<Uuid>,
    chain_group_id: Box<serde_json::value::RawValue>,
    created_at: Option<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct OperatorPolicy {
    id: Uuid,
    name: String,
    description: Option<String>,
    version: u32,
    is_active: bool,
    statements: Vec<Value>,
    chain_policy_id: Box<serde_json::value::RawValue>,
    created_at: Option<String>,
}

impl From<CatalogEntry> for OperatorPolicy {
    fn from(entry: CatalogEntry) -> Self {
        Self {
            id: chain_uuid("policy", entry.id),
            name: entry.name,
            description: (!entry.description.is_empty()).then_some(entry.description),
            version: 1,
            is_active: true,
            statements: Vec::new(),
            chain_policy_id: chain_number(entry.id),
            created_at: None,
        }
    }
}

fn chain_number(id: TokenId) -> Box<serde_json::value::RawValue> {
    serde_json::value::RawValue::from_string(id.to_string()).expect("uint256 decimal is JSON")
}

fn chain_uuid(kind: &str, id: TokenId) -> Uuid {
    const NAMESPACE: Uuid = Uuid::from_u128(0x6f1d4d2a_9b3e_5c7a_8f21_0a1b2c3d4e5f);
    Uuid::new_v5(&NAMESPACE, format!("{kind}:{id}").as_bytes())
}

impl From<Group> for OperatorGroup {
    fn from(group: Group) -> Self {
        Self {
            id: chain_uuid("group", group.id),
            name: group.name,
            description: (!group.description.is_empty()).then_some(group.description),
            is_active: true,
            member_count: group.members.len(),
            policy_ids: group
                .policy_ids
                .into_iter()
                .map(|id| chain_uuid("policy", id))
                .collect(),
            chain_group_id: chain_number(group.id),
            created_at: None,
        }
    }
}

#[derive(Default)]
pub(crate) struct Inventory {
    pub(crate) policies: Vec<CatalogEntry>,
    identities: Vec<TokenId>,
    pub(crate) groups: Vec<Group>,
}

impl Inventory {
    fn memberships(self, token: TokenId) -> Vec<String> {
        if !self.identities.contains(&token) {
            return Vec::new();
        }
        self.groups
            .into_iter()
            .filter(|g| g.members.contains(&token))
            .map(|g| g.name)
            .collect()
    }
}

#[derive(Debug)]
enum ReadError {
    Failure,
    Transport(Option<String>),
    HostRefused(i32),
    Diagnostic(String),
    Rpc(Box<rpc_response::RpcError>),
}

#[derive(Clone, Copy)]
enum RpcRead {
    Contract,
    TransactionQuantity(policy_transaction::QuantityResult),
    Health,
}

impl RpcRead {
    fn limit(self) -> usize {
        match self {
            Self::Contract | Self::TransactionQuantity(_) => 16 * 1024 * 1024,
            Self::Health => 1024 * 1024,
        }
    }
}

impl ReadError {
    fn into_diagnostic(self) -> Option<String> {
        match self {
            Self::Rpc(error) => Some(error.diagnostic),
            Self::Transport(detail) => detail,
            Self::Diagnostic(detail) => Some(detail),
            Self::Failure | Self::HostRefused(_) => None,
        }
    }
}

pub(crate) enum SnapshotError {
    Deadline,
    Unavailable,
}

fn validate_address(address: &str) -> Result<(), ReadError> {
    let hex = address
        .strip_prefix("0x")
        .filter(|s| s.len() == 40)
        .ok_or(ReadError::Failure)?;
    let bytes = HEXLOWER_PERMISSIVE
        .decode(hex.as_bytes())
        .map_err(|_| ReadError::Failure)?;
    if crate::managed_wallet::checksummed(&bytes) != address {
        return Err(ReadError::Failure);
    }
    Ok(())
}

impl Chain {
    #[cfg(test)]
    pub(super) fn for_health_test(endpoint: String) -> Self {
        Self {
            endpoint,
            identity: Some("deployment".into()),
            policy: None,
            group: None,
            signer: Some("configured".into()),
            timeout: Duration::from_secs(1),
        }
    }

    pub(super) fn deployment(enabled: bool, timeout: Duration) -> Option<Self> {
        use std::env;
        if !enabled {
            return None;
        }
        let endpoint = env::var("BLOCKCHAIN_RPC_ENDPOINT")
            .ok()
            .filter(|v| !v.is_empty())?;
        let identity = env::var("IDENTITY_CONTRACT_ADDRESS")
            .ok()
            .filter(|v| !v.is_empty())?;
        let key = zeroize::Zeroizing::new(env::var("BLOCKCHAIN_PRIVATE_KEY").ok()?);
        Some(Self {
            endpoint,
            identity: Some(identity),
            signer: super::address(&key),
            policy: env::var("POLICY_CONTRACT_ADDRESS").ok(),
            group: env::var("GROUP_CONTRACT_ADDRESS").ok(),
            timeout,
        })
    }

    pub(crate) fn validate_signer(&self) -> Result<(), sqlx::Error> {
        if self.signer.is_some() {
            Ok(())
        } else {
            Err(sqlx::Error::Configuration("invalid chain signer".into()))
        }
    }

    pub(crate) async fn groups_for(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user: Uuid,
    ) -> Result<Option<Vec<String>>, sqlx::Error> {
        self.validate_signer()?;
        let mut lookup = tx.begin().await?;
        let token = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT chain_token_id FROM iam_identities WHERE user_id=$1",
        )
        .bind(user)
        .fetch_optional(&mut *lookup)
        .await;
        let id = match token {
            Ok(id) => {
                lookup.commit().await?;
                id.flatten()
            }
            Err(_) => {
                lookup.rollback().await?;
                return Ok(None);
            }
        };
        Ok(self.membership_names(id).await.ok())
    }

    pub(crate) async fn membership_names(
        &self,
        token: Option<i32>,
    ) -> Result<Vec<String>, SnapshotError> {
        let Some(id) = token else {
            return Ok(Vec::new());
        };
        let inventory = self.snapshot().await?;
        Ok(u32::try_from(id)
            .map_or_else(|_| Vec::new(), |n| inventory.memberships(TokenId::from(n))))
    }

    pub(crate) async fn check_user_catalog(&self) -> Result<(), SnapshotError> {
        // The configured Web3 snapshot enumerates groups and policies, without an identity index.
        self.snapshot().await.map(|_| ())
    }

    pub(crate) async fn identity_status(&self, token: &str) -> Result<Option<u8>, SnapshotError> {
        let id = TokenId::from_str_radix(token, 10).map_err(|_| SnapshotError::Unavailable)?;
        let address = self.identity.as_deref().ok_or(SnapshotError::Unavailable)?;
        match self.call(address, identityOfCall { tokenId: id }).await {
            Ok(record) => Ok(Some(record.status)),
            Err(ReadError::Rpc(error))
                if error.code == Some(3) || error.message.starts_with("execution reverted") =>
            {
                Ok(None)
            }
            Err(_) => Err(SnapshotError::Unavailable),
        }
    }

    pub(crate) async fn snapshot(&self) -> Result<Inventory, SnapshotError> {
        tokio::time::timeout(Duration::from_secs(60), self.inventory())
            .await
            .map_err(|_| SnapshotError::Deadline)?
            .map_err(|_| SnapshotError::Unavailable)
    }

    pub(crate) async fn group_catalog(
        &self,
    ) -> Result<Vec<(String, Option<String>, i64)>, SnapshotError> {
        Ok(self
            .snapshot()
            .await?
            .groups
            .into_iter()
            .map(|g| {
                let description = (!g.description.is_empty()).then_some(g.description);
                (g.name, description, g.members.len() as i64)
            })
            .collect())
    }

    pub(crate) async fn operator_groups(&self) -> Result<Vec<OperatorGroup>, SnapshotError> {
        Ok(self
            .snapshot()
            .await?
            .groups
            .into_iter()
            .map(OperatorGroup::from)
            .collect())
    }

    pub(crate) async fn operator_policies(&self) -> Result<Vec<OperatorPolicy>, SnapshotError> {
        Ok(self
            .snapshot()
            .await?
            .policies
            .into_iter()
            .map(OperatorPolicy::from)
            .collect())
    }

    pub(crate) async fn operator_policy(
        &self,
        id: Uuid,
    ) -> Result<Option<OperatorPolicy>, SnapshotError> {
        Ok(self.policy_entry(id).await?.map(OperatorPolicy::from))
    }
    async fn policy_entry(&self, id: Uuid) -> Result<Option<CatalogEntry>, SnapshotError> {
        Ok(self
            .snapshot()
            .await?
            .policies
            .into_iter()
            .find(|entry| chain_uuid("policy", entry.id) == id))
    }

    pub(crate) async fn operator_roles(&self) -> Result<Vec<Value>, SnapshotError> {
        // The contract snapshot enumerates groups and policies. It exposes no IAM role catalog.
        self.snapshot().await.map(|_| Vec::new())
    }

    async fn inventory(&self) -> Result<Inventory, ReadError> {
        let policy = self.policy.as_deref().ok_or(ReadError::Failure)?;
        let policies = self.list(policy, listPoliciesCall {}).await?;
        let group = self.group.as_deref().ok_or(ReadError::Failure)?;
        let entries = self.list(group, listGroupsCall {}).await?;
        // These catalogs enumerate policies and groups. They do not attest identity ownership.
        let mut inventory = Inventory {
            policies,
            ..Default::default()
        };
        for entry in entries {
            let (members, policy_ids) =
                match self.call(group, getMembersCall { groupId: entry.id }).await {
                    Ok(members) => {
                        let policies = self
                            .call(group, getGroupPoliciesCall { groupId: entry.id })
                            .await
                            .unwrap_or_default();
                        (members, policies)
                    }
                    Err(_) => (Vec::new(), Vec::new()),
                };
            inventory.groups.push(Group {
                id: entry.id,
                policy_ids,
                name: entry.name,
                description: entry.description,
                members,
            });
        }
        Ok(inventory)
    }

    async fn list<C: SolCall<Return = Vec<CatalogEntry>>>(
        &self,
        address: &str,
        call: C,
    ) -> Result<Vec<CatalogEntry>, ReadError> {
        match self.call(address, call).await {
            Err(ReadError::Rpc(err)) if err.message.starts_with("execution reverted") => {
                Ok(Vec::new())
            }
            result => result,
        }
    }

    async fn call<C: SolCall>(&self, address: &str, call: C) -> Result<C::Return, ReadError> {
        validate_address(address)?;
        self.rpc("eth_chainId", json!([])).await?;
        let data = format!("0x{}", HEXLOWER.encode(&call.abi_encode()));
        let value = self
            .rpc("eth_call", json!([{"to":address,"data":data},"latest"]))
            .await?;
        self.rpc("eth_chainId", json!([])).await?;
        let raw = value
            .as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .ok_or(ReadError::Failure)?;
        let bytes = HEXLOWER_PERMISSIVE
            .decode(raw.as_bytes())
            .map_err(|_| ReadError::Failure)?;
        C::abi_decode_returns_validate(&bytes).map_err(|_| ReadError::Failure)
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, ReadError> {
        self.rpc_bounded(method, params, RpcRead::Contract).await
    }

    pub(super) async fn health_block(&self) -> Result<Value, String> {
        self.rpc_bounded("eth_blockNumber", json!([]), RpcRead::Health)
            .await
            .map_err(|error| {
                error
                    .into_diagnostic()
                    .unwrap_or_else(|| "Invalid JSON-RPC response".into())
            })
    }

    async fn rpc_bounded(
        &self,
        method: &str,
        params: Value,
        read: RpcRead,
    ) -> Result<Value, ReadError> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
        for attempt in 0..5 {
            match self.request(&CLIENT, &body, read).await {
                Err(ReadError::HostRefused(_))
                    if attempt == 3 && matches!(read, RpcRead::Health) =>
                {
                    tokio::time::sleep(Duration::from_millis(125 << attempt)).await;
                    return self.retry_health_by_address(&body).await;
                }
                Err(ReadError::Transport(_) | ReadError::HostRefused(_)) if attempt < 4 => {
                    tokio::time::sleep(Duration::from_millis(125 << attempt)).await
                }
                result => return result,
            }
        }
        unreachable!("final RPC attempt always returns its result")
    }

    async fn request(
        &self,
        client: &Client,
        body: &str,
        read: RpcRead,
    ) -> Result<Value, ReadError> {
        let mut response = client
            .post(&self.endpoint)
            .timeout(self.timeout)
            .header("Content-Type", "application/json")
            .body(body.to_owned())
            .send()
            .await
            .map_err(|e| transport::request_error(&self.endpoint, &e))?;
        if response.status().is_client_error() || response.status().is_server_error() {
            return Err(transport::http_error(&self.endpoint, &response));
        }
        let mut body = Vec::new();
        while let Some(piece) = response
            .chunk()
            .await
            .map_err(|e| transport::request_error(&self.endpoint, &e))?
        {
            if piece.len() > read.limit() - body.len() {
                return match read {
                    RpcRead::Contract | RpcRead::TransactionQuantity(_) => Err(ReadError::Failure),
                    RpcRead::Health => {
                        large_health::read(&self.endpoint, response, &body, &piece).await
                    }
                };
            }
            body.extend_from_slice(&piece);
        }
        rpc_response::decode(&body, read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deployment_signer_is_validated_before_using_postgres_roles() {
        let mut chain = Chain::for_health_test("http://localhost".into());
        let settings = ChainSettings::with_deployment(chain.clone());
        assert!(settings.iam_source().await.unwrap().is_none());
        chain.signer = None;
        let settings = ChainSettings::with_deployment(chain);
        assert!(settings.iam_source().await.is_err());
    }

    #[test]
    fn role_groups_require_an_identity_in_the_same_inventory() {
        let token = TokenId::from(17);
        let groups = vec![Group {
            id: TokenId::from(1),
            policy_ids: Vec::new(),
            name: "app:owner".into(),
            description: String::new(),
            members: vec![token],
        }];
        assert!(
            Inventory {
                policies: vec![],
                identities: vec![],
                groups: groups.clone()
            }
            .memberships(token)
            .is_empty()
        );
        assert_eq!(
            Inventory {
                policies: vec![],
                identities: vec![token],
                groups
            }
            .memberships(token),
            ["app:owner"]
        );
    }

    #[test]
    fn operator_groups_preserve_wide_chain_ids_and_ordered_policy_references() {
        let group = Group {
            id: TokenId::MAX,
            name: "team".into(),
            description: String::new(),
            members: vec![TokenId::from(9)],
            policy_ids: vec![TokenId::from(7), TokenId::from(2)],
        };
        let record = OperatorGroup::from(group);
        let encoded = serde_json::to_string(&record).unwrap();
        assert!(encoded.contains(&format!(r#""chain_group_id":{}"#, TokenId::MAX)));
        assert_eq!(
            record.policy_ids,
            [
                chain_uuid("policy", TokenId::from(7)),
                chain_uuid("policy", TokenId::from(2))
            ]
        );
        assert_ne!(record.id, chain_uuid("policy", TokenId::MAX));
    }

    #[tokio::test]
    async fn reads_members_from_the_group_catalog_without_treating_it_as_identity_proof() {
        use axum::{Json, Router, routing::post};
        async fn rpc(Json(req): Json<Value>) -> Json<Value> {
            let result = match req["method"].as_str().unwrap() {
                "eth_chainId" => json!("0x1"),
                "eth_call" => {
                    let data = req["params"][0]["data"].as_str().unwrap();
                    let selector = HEXLOWER.decode(&data.as_bytes()[2..10]).unwrap();
                    let bytes = match selector.as_slice().try_into().unwrap() {
                        listPoliciesCall::SELECTOR => listPoliciesCall::abi_encode_returns(&vec![]),
                        listGroupsCall::SELECTOR => {
                            listGroupsCall::abi_encode_returns(&vec![CatalogEntry {
                                id: TokenId::from(2),
                                name: "rp:app:owner".into(),
                                description: String::new(),
                                creator: Default::default(),
                                count: TokenId::from(1),
                                active: true,
                                createdAt: TokenId::from(0),
                            }])
                        }
                        getMembersCall::SELECTOR => {
                            getMembersCall::abi_encode_returns(&vec![TokenId::from(17)])
                        }
                        getGroupPoliciesCall::SELECTOR => {
                            getGroupPoliciesCall::abi_encode_returns(&vec![])
                        }
                        _ => panic!("unexpected contract read"),
                    };
                    json!(format!("0x{}", HEXLOWER.encode(&bytes)))
                }
                _ => panic!("unexpected RPC method"),
            };
            Json(json!({"jsonrpc":"2.0","id":req["id"],"result":result}))
        }
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let chain = Chain {
            identity: None,
            endpoint: format!("http://{}", socket.local_addr().unwrap()),
            policy: Some(format!("0x{}", "11".repeat(20))),
            group: Some(format!("0x{}", "22".repeat(20))),
            signer: Some("0x0000000000000000000000000000000000000001".into()),
            timeout: Duration::from_secs(2),
        };
        let server = tokio::spawn(async move {
            axum::serve(socket, Router::new().route("/", post(rpc)))
                .await
                .unwrap()
        });
        let inventory = chain.inventory().await.unwrap();
        let token = TokenId::from(17);
        assert_eq!(inventory.groups.len(), 1);
        assert_eq!(inventory.groups[0].name, "rp:app:owner");
        assert_eq!(inventory.groups[0].members, vec![token]);
        assert!(inventory.memberships(token).is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn retries_a_transient_http_failure_during_a_chain_read() {
        use axum::{Json, Router, http::StatusCode, routing::post};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let count = Arc::new(AtomicUsize::new(0));
        let requests = count.clone();
        let app = Router::new().route(
            "/",
            post(move || {
                let index = requests.fetch_add(1, Ordering::Relaxed);
                async move {
                    if index == 0 {
                        (StatusCode::SERVICE_UNAVAILABLE, Json(Value::Null))
                    } else {
                        (
                            StatusCode::OK,
                            Json(json!({"jsonrpc":"2.0","id":1,"result":"0x1"})),
                        )
                    }
                }
            }),
        );
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let chain = Chain {
            identity: None,
            endpoint: format!("http://{}", socket.local_addr().unwrap()),
            policy: None,
            group: None,
            signer: Some("0x0000000000000000000000000000000000000001".into()),
            timeout: Duration::from_secs(2),
        };
        let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
        assert_eq!(
            chain.rpc("eth_chainId", json!([])).await.unwrap(),
            json!("0x1")
        );
        assert_eq!(count.load(Ordering::Relaxed), 2);
        server.abort();
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn unlinked_user_and_unavailable_authority_never_use_a_local_assignment() {
        use crate::chain_settings::Update;
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE iam_identities(user_id uuid,chain_token_id int)")
            .execute(&mut *tx)
            .await
            .unwrap();
        let state = ChainSettings::default();
        state
            .update(Update {
                enabled: Some(true),
                private_key: Some(zeroize::Zeroizing::new(format!("{:064x}", 1))),
                rpc_url: Some("http://127.0.0.1".into()),
                identity_contract_address: Some("identity".into()),
                ..Default::default()
            })
            .await;
        let chain = state.membership_source().await.unwrap();
        let user = Uuid::new_v4();
        assert_eq!(chain.groups_for(&mut tx, user).await.unwrap(), Some(vec![]));
        sqlx::query("INSERT INTO iam_identities VALUES ($1,17)")
            .bind(user)
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(chain.groups_for(&mut tx, user).await.unwrap(), None);
    }
}
