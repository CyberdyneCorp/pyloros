//! Attachment discovery must succeed before the service prepares a deletion.
use super::*;
use axum::{Json, Router, routing::post};

#[tokio::test]
async fn attached_and_unreadable_groups_stop_policy_deletion_before_nonce_lookup() {
    const POLICY: &str = "0x0000000000000000000000000000000000000011";
    const GROUP: &str = "0x0000000000000000000000000000000000000022";
    const UNREADABLE: &str = "0x0000000000000000000000000000000000000033";
    async fn rpc(Json(req): Json<Value>) -> Json<Value> {
        let entries = vec![CatalogEntry {
            id: TokenId::from(7),
            name: "entry".into(),
            description: String::new(),
            creator: Default::default(),
            count: TokenId::ZERO,
            active: true,
            createdAt: TokenId::ZERO,
        }];
        let result = match req["method"].as_str().unwrap() {
            "eth_chainId" => json!("0x1"),
            "eth_call" => {
                let target = req["params"][0]["to"].as_str().unwrap();
                let data = req["params"][0]["data"].as_str().unwrap();
                let selector = &HEXLOWER.decode(&data.as_bytes()[2..10]).unwrap()[..];
                let bytes = if selector == listPoliciesCall::SELECTOR {
                    assert_eq!(target, POLICY);
                    listPoliciesCall::abi_encode_returns(&entries)
                } else if selector == listGroupsCall::SELECTOR {
                    listGroupsCall::abi_encode_returns(&entries)
                } else {
                    assert_eq!(selector, getGroupPoliciesCall::SELECTOR);
                    if target == UNREADABLE {
                        return Json(
                            json!({"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}),
                        );
                    }
                    assert_eq!(target, GROUP);
                    getGroupPoliciesCall::abi_encode_returns(&vec![TokenId::from(7)])
                };
                json!(format!("0x{}", HEXLOWER.encode(&bytes)))
            }
            other => panic!("unexpected {other}"),
        };
        Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
    }
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut chain = Chain::for_health_test(format!("http://{}", socket.local_addr().unwrap()));
    chain.policy = Some(POLICY.into());
    chain.group = Some(GROUP.into());
    let server = tokio::spawn(async move {
        axum::serve(socket, Router::new().route("/", post(rpc)))
            .await
            .unwrap()
    });
    let id = chain_uuid("policy", TokenId::from(7));
    let mutation = IamMutation::DeletePolicy(id);
    assert!(
        matches!(chain.submit_mutation(&mutation).await,Err(PrepareError::AttachedPolicy(actual)) if actual==id)
    );
    chain.group = Some(UNREADABLE.into());
    assert!(matches!(
        chain.submit_mutation(&mutation).await,
        Err(PrepareError::Rpc(_))
    ));
    server.abort();
}
