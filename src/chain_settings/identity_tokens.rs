//! Identity tokens belong to the provider selected for a request.
use super::{Chain, ChainSettings, SnapshotError};
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) enum TokenProvider {
    Local(Arc<Mutex<Vec<u8>>>),
    Remote(Chain),
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
                Ok(TokenProvider::Remote(chain))
            }
            None => Ok(TokenProvider::Local(state.local_tokens.clone())),
        }
    }
}

impl TokenProvider {
    pub(crate) async fn status(&self, token: &str) -> Result<Option<u8>, SnapshotError> {
        match self {
            Self::Remote(chain) => chain.identity_status(token).await,
            Self::Local(tokens) => {
                let index = token.parse::<usize>().ok().and_then(|n| n.checked_sub(1));
                let tokens = tokens.lock().await;
                Ok(index.and_then(|i| tokens.get(i).copied()))
            }
        }
    }
}
