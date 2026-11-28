use super::ChainSettings;
use serde_json::{Value, json};
use std::time::Duration;

impl ChainSettings {
    pub(crate) async fn health(&self) -> Result<Value, ()> {
        let Some(target) = self.provider().await else {
            return Ok(
                json!({"enabled":false,"available":false,"identity_contract_address":null,
                "rpc_endpoint":null,"error":"null provider (no RPC configured)"}),
            );
        };
        if target.validate_signer().is_err() {
            return Err(());
        }
        let error = match tokio::time::timeout(Duration::from_secs(5), target.health_block()).await
        {
            Err(_) => Some(String::new()),
            Ok(result) => result.and_then(|value| block_result(&value)).err(),
        };
        Ok(
            json!({"enabled":true,"available":error.is_none(),"identity_contract_address":target.identity,
                "rpc_endpoint":target.endpoint,"error":error}),
        )
    }
}

fn block_result(result: &Value) -> Result<(), String> {
    if let Some(raw) = result.as_str()
        && crate::unicode_decimal::hexadecimal_magnitude(raw).is_none()
    {
        return Err(format!(
            "invalid literal for int() with base 16: {}",
            crate::browser_prompt::quoted_string(raw)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn runtime_provider_precedes_deployment_and_recovers_without_restart() {
        use crate::chain_settings::Update;
        use axum::{Json, Router, routing::post};

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", socket.local_addr().unwrap());
        let app = Router::new().route(
            "/",
            post(|Json(req): Json<Value>| async move {
                assert_eq!(req["method"], "eth_blockNumber");
                assert_eq!(req["params"], json!([]));
                Json(json!({"id":req["id"],"jsonrpc":"2.0","result":"0x8"}))
            }),
        );
        let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
        let settings = ChainSettings {
            deployment: Some(super::super::Chain::for_health_test(endpoint.clone())),
            ..Default::default()
        };
        let report = settings.health().await.unwrap();
        assert_eq!(report["identity_contract_address"], "deployment");
        assert_eq!(report["available"], true);
        settings
            .update(Update {
                enabled: Some(true),
                rpc_url: Some(format!("{endpoint}/offline")),
                identity_contract_address: Some("runtime".into()),
                private_key: Some(zeroize::Zeroizing::new(format!("{:064x}", 1))),
                ..Default::default()
            })
            .await;
        let report = settings.health().await.unwrap();
        assert_eq!(report["available"], false);
        assert_eq!(report["identity_contract_address"], "runtime");
        assert_eq!(
            report["error"],
            format!("404, message='Not Found', url='{endpoint}/offline'")
        );
        settings
            .update(Update {
                rpc_url: Some(endpoint),
                ..Default::default()
            })
            .await;
        let report = settings.health().await.unwrap();
        assert_eq!(report["available"], true);
        assert!(report["error"].is_null());
        server.abort();
    }

    #[test]
    fn block_number_reports_invalid_hexadecimal_values() {
        for value in ["0x0", "0x_fa", "a_b", "٠xA", "+１２"] {
            assert_eq!(block_result(&json!(value)), Ok(()));
        }
        assert!(crate::unicode_decimal::hexadecimal_magnitude("0x__fa").is_none());
        assert_eq!(
            block_result(&json!("0x")),
            Err("invalid literal for int() with base 16: '0x'".into())
        );
    }
}
