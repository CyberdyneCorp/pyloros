use super::{ChainSettings, address};
use reqwest::Client;
use serde_json::{Value, json};
use std::{env, error::Error, time::Duration};
use zeroize::Zeroizing;

#[derive(Clone)]
struct Target {
    rpc: String,
    identity: String,
    valid_signer: bool,
}

pub(crate) struct Monitor {
    client: Client,
    fallback: Option<Target>,
    timeout: Duration,
}

impl Monitor {
    pub(crate) fn configured() -> Result<Self, Box<dyn Error>> {
        let timeout =
            env::var("BLOCKCHAIN_RPC_TIMEOUT_S").map_or(Ok(10.0), |v| v.parse::<f64>())?;
        Ok(Self {
            client: Client::builder().build()?,
            fallback: deployment_target(crate::config::flag("BLOCKCHAIN_ENABLED")?),
            timeout: Duration::try_from_secs_f64(timeout)?.min(Duration::from_secs(5)),
        })
    }

    pub(crate) async fn read(&self, settings: &ChainSettings) -> Result<Value, ()> {
        let runtime = settings.state.read().await;
        let view = runtime.view();
        let target = if view.is_configured {
            Some(Target {
                rpc: view.rpc_url.unwrap_or_default(),
                identity: view.identity_contract_address.unwrap_or_default(),
                valid_signer: view.signer_address.is_some(),
            })
        } else {
            self.fallback.clone()
        };
        drop(runtime);
        let Some(target) = target else {
            return Ok(
                json!({"enabled":false,"available":false,"identity_contract_address":null,
                "rpc_endpoint":null,"error":"null provider (no RPC configured)"}),
            );
        };
        if !target.valid_signer {
            return Err(());
        }
        let error = self.block_number(&target.rpc).await.err();
        Ok(
            json!({"enabled":true,"available":error.is_none(),"identity_contract_address":target.identity,
                "rpc_endpoint":target.rpc,"error":error}),
        )
    }

    async fn block_number(&self, rpc: &str) -> Result<(), String> {
        let mut response = self
            .client
            .post(rpc)
            .header("Content-Type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(transport)?;
        let status = response.status();
        if status.is_client_error() || status.is_server_error() {
            let reason = status.canonical_reason().unwrap_or("");
            return Err(format!(
                "{}, message={}, url={}",
                status.as_u16(),
                diagnostic(&json!(reason)),
                diagnostic(&json!(rpc))
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            if chunk.len() > 1024 * 1024 - bytes.len() {
                return Err("RPC response exceeds size limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let doc = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        block_result(&doc)
    }
}

fn deployment_target(enabled: bool) -> Option<Target> {
    if !enabled {
        return None;
    }
    let rpc = env::var("BLOCKCHAIN_RPC_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty())?;
    let identity = env::var("IDENTITY_CONTRACT_ADDRESS")
        .ok()
        .filter(|s| !s.is_empty())?;
    let key = Zeroizing::new(env::var("BLOCKCHAIN_PRIVATE_KEY").ok()?);
    Some(Target {
        rpc,
        identity,
        valid_signer: address(&key).is_some(),
    })
}

fn transport(e: reqwest::Error) -> String {
    if e.is_timeout() {
        String::new()
    } else {
        e.without_url().to_string()
    }
}

fn block_result(doc: &Value) -> Result<(), String> {
    if doc["jsonrpc"] != "2.0" || doc["id"] != 1 {
        return Err("Invalid JSON-RPC response".into());
    }
    if let Some(err) = doc.get("error") {
        return Err(diagnostic(err));
    }
    let result = doc.get("result").ok_or("Missing JSON-RPC result")?;
    if let Some(raw) = result.as_str() {
        let trimmed = raw.trim();
        let number = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
        let digits = number
            .strip_prefix("0x")
            .or_else(|| number.strip_prefix("0X"))
            .unwrap_or(number);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "invalid literal for int() with base 16: {}",
                diagnostic(result)
            ));
        }
    }
    Ok(())
}

fn diagnostic(value: &Value) -> String {
    match value {
        Value::String(s) => {
            let delimiter = if s.contains('\'') && !s.contains('"') {
                '"'
            } else {
                '\''
            };
            let escaped = s
                .replace('\\', "\\\\")
                .replace(delimiter, &format!("\\{delimiter}"))
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t");
            format!("{delimiter}{escaped}{delimiter}")
        }
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(key, v)| format!("{}: {}", diagnostic(&json!(key)), diagnostic(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Array(xs) => format!(
            "[{}]",
            xs.iter().map(diagnostic).collect::<Vec<_>>().join(", ")
        ),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => n.to_string(),
    }
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
        let monitor = Monitor {
            client: Client::new(),
            fallback: Some(Target {
                rpc: endpoint.clone(),
                identity: "deployment".into(),
                valid_signer: true,
            }),
            timeout: Duration::from_secs(1),
        };
        let settings = ChainSettings::default();
        let report = monitor.read(&settings).await.unwrap();
        assert_eq!(report["identity_contract_address"], "deployment");
        assert_eq!(report["available"], true);
        settings
            .update(Update {
                enabled: Some(true),
                rpc_url: Some(format!("{endpoint}/offline")),
                identity_contract_address: Some("runtime".into()),
                private_key: Some(Zeroizing::new(format!("{:064x}", 1))),
                ..Default::default()
            })
            .await;
        let report = monitor.read(&settings).await.unwrap();
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
        let report = monitor.read(&settings).await.unwrap();
        assert_eq!(report["available"], true);
        assert!(report["error"].is_null());
        server.abort();
    }

    #[test]
    fn distinguishes_rpc_outage_from_genesis_and_rejects_an_unrelated_response() {
        let mut response = json!({"id":1,"jsonrpc":"2.0","result":"0x0"});
        assert_eq!(block_result(&response), Ok(()));
        response["id"] = json!(2);
        assert!(block_result(&response).is_err());
        let failed = json!({"id":1,"jsonrpc":"2.0","error":{"code":-32000,"message":"offline"}});
        assert_eq!(
            block_result(&failed),
            Err("{'code': -32000, 'message': 'offline'}".into())
        );
    }
}
