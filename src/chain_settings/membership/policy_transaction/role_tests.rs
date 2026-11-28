//! Role writes must reach submission before the caller can report their outcome.
use super::*;
use axum::{Json, Router, routing::post};

async fn provider(Json(req): Json<Value>) -> Json<Value> {
    let result = match req["method"].as_str().unwrap() {
        "eth_call" => {
            let call = req["params"][0]["data"].as_str().unwrap();
            let selector = HEXLOWER.decode(&call.as_bytes()[2..10]).unwrap();
            let encoded = if selector == listGroupsCall::SELECTOR {
                listGroupsCall::abi_encode_returns(&vec![CatalogEntry {
                    id: TokenId::from(7),
                    name: "rp:client:reader".into(),
                    description: String::new(),
                    creator: Default::default(),
                    count: TokenId::ZERO,
                    active: true,
                    createdAt: TokenId::ZERO,
                }])
            } else if selector == listPoliciesCall::SELECTOR {
                listPoliciesCall::abi_encode_returns(&Vec::new())
            } else {
                getMembersCall::abi_encode_returns(&Vec::new())
            };
            json!(format!("0x{}", HEXLOWER.encode(&encoded)))
        }
        "eth_getTransactionCount" | "eth_maxPriorityFeePerGas" | "eth_chainId" => json!("0x1"),
        "eth_estimateGas" => json!("0x10000"),
        "eth_getBlockByNumber" => json!({"baseFeePerGas":"0x1"}),
        "eth_sendRawTransaction" => {
            return Json(json!({"jsonrpc":"2.0","id":req["id"],
            "error":{"code":-32000,"message":"submission refused"}}));
        }
        other => panic!("unexpected {other}"),
    };
    Json(json!({"jsonrpc":"2.0","id":req["id"],"result":result}))
}

#[tokio::test]
async fn role_membership_and_catalog_writes_propagate_submission_refusal() {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = "0x0000000000000000000000000000000000000001".to_owned();
    let chain = Chain {
        endpoint: format!("http://{}", socket.local_addr().unwrap()),
        signer: Some(address.clone()),
        signing_key: Some(k256::SecretKey::from_slice(&[1; 32]).unwrap()),
        identity: None,
        group: Some(address.clone()),
        policy: Some(address),
        timeout: Duration::from_secs(2),
    };
    let server = tokio::spawn(async move {
        axum::serve(socket, Router::new().route("/", post(provider)))
            .await
            .unwrap()
    });
    for add in [true, false] {
        assert!(
            matches!(chain.change_role_membership(TokenId::from(7),9,add).await,
            Err(PrepareError::Rpc(detail)) if detail.contains("submission refused"))
        );
    }
    assert!(matches!(chain.delete_role_group(TokenId::from(7)).await,
        Err(PrepareError::Rpc(detail)) if detail.contains("submission refused")));
    assert!(
        matches!(chain.create_group_entry("rp:client:editor", None).await,
        Err(PrepareError::Rpc(detail)) if detail.contains("submission refused"))
    );
    server.abort();
}
