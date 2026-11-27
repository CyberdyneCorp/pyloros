//! Read the authority's IAM inventory without sending transactions.
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
    function listPolicies() external view returns (CatalogEntry[]);
    function listGroups() external view returns (CatalogEntry[]);
    function getMembers(uint256 groupId) external view returns (uint256[]);
    function getGroupPolicies(uint256 groupId) external view returns (uint256[]);
}

static CLIENT: LazyLock<Client> = LazyLock::new(Client::new);

pub(crate) struct Chain {
    endpoint: String,
    policy: Option<String>,
    group: Option<String>,
    signer_valid: bool,
    timeout: Duration,
}

impl ChainSettings {
    pub(crate) async fn membership_source(&self) -> Option<Chain> {
        let state = self.state.read().await;
        let view = state.view();
        view.is_configured.then(|| Chain {
            endpoint: view.rpc_url.unwrap_or_default(),
            policy: view.policy_contract_address,
            group: view.group_contract_address,
            signer_valid: view.signer_address.is_some(),
            timeout: self.rpc_timeout.unwrap_or(Duration::from_secs(10)),
        })
    }
}

type TokenId = <sol!(uint256) as alloy_sol_types::SolType>::RustType;

#[derive(Default)]
struct Inventory {
    identities: Vec<TokenId>,
    groups: Vec<(String, Vec<TokenId>)>,
}

impl Inventory {
    fn memberships(self, token: TokenId) -> Vec<String> {
        if !self.identities.contains(&token) {
            return Vec::new();
        }
        self.groups
            .into_iter()
            .filter(|(_, members)| members.contains(&token))
            .map(|(name, _)| name)
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ReadError {
    Failure,
    Transport,
    Reverted,
}

impl Chain {
    pub(crate) fn validate_signer(&self) -> Result<(), sqlx::Error> {
        if self.signer_valid {
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
        let Some(id) = id else {
            return Ok(Some(Vec::new()));
        };
        let inventory = tokio::time::timeout(Duration::from_secs(60), self.inventory())
            .await
            .ok()
            .and_then(Result::ok);
        Ok(inventory.map(|i| {
            u32::try_from(id).map_or_else(|_| Vec::new(), |n| i.memberships(TokenId::from(n)))
        }))
    }

    async fn inventory(&self) -> Result<Inventory, ReadError> {
        let policy = self.policy.as_deref().ok_or(ReadError::Failure)?;
        self.list(policy, listPoliciesCall {}).await?;
        let group = self.group.as_deref().ok_or(ReadError::Failure)?;
        let entries = self.list(group, listGroupsCall {}).await?;
        // These catalogs enumerate policies and groups. They do not attest identity ownership.
        let mut inventory = Inventory::default();
        for entry in entries {
            let members = match self.call(group, getMembersCall { groupId: entry.id }).await {
                Ok(members) => {
                    let _ = self
                        .call(group, getGroupPoliciesCall { groupId: entry.id })
                        .await;
                    members
                }
                Err(_) => Vec::new(),
            };
            inventory.groups.push((entry.name, members));
        }
        Ok(inventory)
    }

    async fn list<C: SolCall<Return = Vec<CatalogEntry>>>(
        &self,
        address: &str,
        call: C,
    ) -> Result<Vec<CatalogEntry>, ReadError> {
        match self.call(address, call).await {
            Err(ReadError::Reverted) => Ok(Vec::new()),
            result => result,
        }
    }

    async fn call<C: SolCall>(&self, address: &str, call: C) -> Result<C::Return, ReadError> {
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
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
        for attempt in 0..5 {
            match self.request(&body).await {
                Err(ReadError::Transport) if attempt < 4 => {
                    tokio::time::sleep(Duration::from_millis(125 << attempt)).await
                }
                result => return result,
            }
        }
        Err(ReadError::Transport)
    }

    async fn request(&self, body: &str) -> Result<Value, ReadError> {
        let mut response = CLIENT
            .post(&self.endpoint)
            .timeout(self.timeout)
            .header("Content-Type", "application/json")
            .body(body.to_owned())
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|_| ReadError::Transport)?;
        let mut body = Vec::new();
        while let Some(piece) = response.chunk().await.map_err(|_| ReadError::Transport)? {
            if piece.len() > 16 * 1024 * 1024 - body.len() {
                return Err(ReadError::Failure);
            }
            body.extend_from_slice(&piece);
        }
        let mut doc: Value = serde_json::from_slice(&body).map_err(|_| ReadError::Failure)?;
        if doc["jsonrpc"] != "2.0" || doc["id"] != 1 {
            return Err(ReadError::Failure);
        }
        if let Some(error) = doc.get("error") {
            return Err(
                if error["message"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("execution reverted"))
                {
                    ReadError::Reverted
                } else {
                    ReadError::Failure
                },
            );
        }
        doc.get_mut("result")
            .map(Value::take)
            .ok_or(ReadError::Failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_groups_require_an_identity_in_the_same_inventory() {
        let token = TokenId::from(17);
        let groups = vec![("app:owner".to_owned(), vec![token])];
        assert!(
            Inventory {
                identities: vec![],
                groups: groups.clone()
            }
            .memberships(token)
            .is_empty()
        );
        assert_eq!(
            Inventory {
                identities: vec![token],
                groups
            }
            .memberships(token),
            ["app:owner"]
        );
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
            endpoint: format!("http://{}", socket.local_addr().unwrap()),
            policy: Some(format!("0x{}", "11".repeat(20))),
            group: Some(format!("0x{}", "22".repeat(20))),
            signer_valid: true,
            timeout: Duration::from_secs(2),
        };
        let server = tokio::spawn(async move {
            axum::serve(socket, Router::new().route("/", post(rpc)))
                .await
                .unwrap()
        });
        let inventory = chain.inventory().await.unwrap();
        let token = TokenId::from(17);
        assert_eq!(inventory.groups, vec![("rp:app:owner".into(), vec![token])]);
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
            endpoint: format!("http://{}", socket.local_addr().unwrap()),
            policy: None,
            group: None,
            signer_valid: true,
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
