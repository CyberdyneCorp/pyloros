use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use tokio::{net::TcpListener, process::Command};

#[tokio::test]
async fn receipt_inspection_uses_only_the_requested_hash_and_needs_no_signer() {
    let hash = format!("0x{}", "ab".repeat(32));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let expected = hash.clone();
    let app = Router::new().route("/", post(move |Json(request): Json<Value>| {
        let expected = expected.clone();
        async move {
            assert_eq!(request, json!({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":[expected]}));
            Json(json!({"jsonrpc":"2.0","id":1,"result":null}))
        }
    }));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let result = Command::new(env!("CARGO_BIN_EXE_pyloros"))
        .args(["--inspect-iam-receipt", &hash])
        .env_remove("DATABASE_URL")
        .env_remove("BLOCKCHAIN_PRIVATE_KEY")
        .env("BLOCKCHAIN_RPC_ENDPOINT", endpoint)
        .output()
        .await
        .unwrap();
    server.abort();
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap(),
        json!({"requested_hash":hash,"outcome":"receipt_unavailable"})
    );
}
