//! Identity tokens belong to the provider selected for a request.
use super::{Chain, ChainSettings, SnapshotError};
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) enum TokenProvider {
    Local(Arc<Mutex<Vec<u8>>>),
    Remote(Chain, Arc<Mutex<()>>),
}

impl ChainSettings {
    pub(crate) async fn token_provider(&self) -> Result<TokenProvider, sqlx::Error> {
        let state = self.state.read().await;
        match self
            .runtime_chain(&state)
            .or_else(|| self.deployment.clone())
        {
            Some(chain) => {
                chain.validate_signer()?;
                Ok(TokenProvider::Remote(chain, state.token_writes.clone()))
            }
            None => Ok(TokenProvider::Local(state.local_tokens.clone())),
        }
    }
}

impl TokenProvider {
    pub(crate) async fn status(&self, token: &str) -> Result<Option<u8>, SnapshotError> {
        match self {
            Self::Remote(chain, _) => chain.identity_status(token).await,
            Self::Local(tokens) => {
                let index = token.parse::<usize>().ok().and_then(|n| n.checked_sub(1));
                let tokens = tokens.lock().await;
                Ok(index.and_then(|i| tokens.get(i).copied()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_settings::Update;

    #[tokio::test]
    async fn remote_token_writes_share_one_lock_until_settings_reload() {
        let settings = ChainSettings::default();
        settings
            .update(Update {
                enabled: Some(true),
                rpc_url: Some("http://localhost".into()),
                private_key: Some(zeroize::Zeroizing::new(format!("{:064x}", 1))),
                identity_contract_address: Some("identity".into()),
                ..Default::default()
            })
            .await;
        let writes = || async {
            let TokenProvider::Remote(_, writes) = settings.token_provider().await.unwrap() else {
                panic!("expected the configured provider")
            };
            writes
        };
        let first = writes().await;
        let _pending = first.lock().await;
        assert!(writes().await.try_lock().is_err());
        settings.update(Update::default()).await;
        assert!(writes().await.try_lock().is_ok());
    }
}
