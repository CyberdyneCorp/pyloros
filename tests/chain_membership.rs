use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use tokio::{net::TcpListener, process::Command};

#[tokio::test]
async fn membership_report_uses_the_requested_canonical_block() {
    let contract = "0x1111111111111111111111111111111111111111";
    let block = format!("0x{}", "ab".repeat(32));
    let expected = block.clone();
    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let result = match req["method"].as_str() {
                Some("eth_chainId") => json!("0x1"),
                Some("eth_call") => {
                    assert_eq!(req["params"][0]["to"], contract);
                    assert_eq!(
                        req["params"][1],
                        json!({"blockHash":expected,"requireCanonical":true})
                    );
                    let selector = alloy_primitives::keccak256("getMembers(uint256)");
                    assert_eq!(
                        req["params"][0]["data"],
                        format!("0x{}{:064x}", &format!("{selector:x}")[..8], 3)
                    );
                    json!(format!("0x{:064x}{:064x}{:064x}", 32, 1, 7))
                }
                _ => panic!("unexpected RPC method"),
            };
            async move { Json(json!({"jsonrpc":"2.0","id":1,"result":result})) }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    for (identity, member) in [("7", true), ("8", false)] {
        let output = Command::new(env!("CARGO_BIN_EXE_pyloros"))
            .args(["--inspect-iam-membership", contract, "3", identity, &block])
            .env_remove("DATABASE_URL")
            .env_remove("BLOCKCHAIN_PRIVATE_KEY")
            .env("BLOCKCHAIN_RPC_ENDPOINT", &endpoint)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!({"contract":contract,"block_hash":block,"group_id":"3","identity_token_id":identity,"member":member})
        );
    }
    server.abort();
}
