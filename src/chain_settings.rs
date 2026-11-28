//! Mutable chain configuration and its credential-free operator view.
mod health;
mod identity_tokens;
mod membership;
use data_encoding::HEXLOWER_PERMISSIVE;
pub(crate) use identity_tokens::TokenProvider;
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
pub use membership::inspection::{MembershipObservation, inspect_membership};
pub use membership::receipt::{
    ReceiptObservation, inspect_receipt, inspect_receipt_for, wait_for_receipt,
};
pub(crate) use membership::{
    Chain, Inventory, SnapshotError,
    policy_transaction::{IamMutation, PrepareError},
};
use serde::Serialize;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

#[derive(Default)]
pub struct ChainSettings {
    deployment: Option<Chain>,
    rpc_timeout: Option<std::time::Duration>,
    state: RwLock<Configuration>,
    pub(crate) admin_updates: tokio::sync::Mutex<()>,
}

#[derive(Default)]
pub struct Update {
    pub enabled: Option<bool>,
    pub rpc_url: Option<String>,
    pub private_key: Option<Zeroizing<String>>,
    pub identity_contract_address: Option<String>,
    pub policy_contract_address: Option<String>,
    pub group_contract_address: Option<String>,
}

#[derive(Default)]
struct Configuration {
    token_writes: std::sync::Arc<tokio::sync::Mutex<()>>,
    local_tokens: std::sync::Arc<tokio::sync::Mutex<Vec<u8>>>,
    values: Update,
    signer_address: Option<String>,
}

#[derive(Serialize)]
pub struct View {
    enabled: bool,
    rpc_url: Option<String>,
    has_private_key: bool,
    pub(crate) signer_address: Option<String>,
    identity_contract_address: Option<String>,
    policy_contract_address: Option<String>,
    group_contract_address: Option<String>,
    is_configured: bool,
}

impl ChainSettings {
    pub(crate) fn configured() -> Result<Self, Box<dyn std::error::Error>> {
        let timeout = rpc_timeout()?;
        Ok(Self {
            deployment: Chain::deployment(crate::config::flag("BLOCKCHAIN_ENABLED")?, timeout),
            rpc_timeout: Some(timeout),
            ..Default::default()
        })
    }

    #[cfg(test)]
    pub(crate) fn with_deployment(chain: Chain) -> Self {
        Self {
            deployment: Some(chain),
            ..Default::default()
        }
    }

    pub async fn view(&self) -> View {
        self.state.read().await.view()
    }

    pub async fn update(&self, patch: Update) -> View {
        let signer = patch
            .private_key
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| address(s));
        let mut state = self.state.write().await;
        if let Some(address) = signer {
            state.signer_address = address;
        }
        state.local_tokens = Default::default();
        state.token_writes = Default::default();
        let current = &mut state.values;
        merge(&mut current.enabled, patch.enabled);
        merge(&mut current.rpc_url, patch.rpc_url);
        merge(&mut current.private_key, patch.private_key);
        merge(
            &mut current.identity_contract_address,
            patch.identity_contract_address,
        );
        merge(
            &mut current.group_contract_address,
            patch.group_contract_address,
        );
        merge(
            &mut current.policy_contract_address,
            patch.policy_contract_address,
        );
        state.view()
    }
}

fn rpc_timeout() -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let seconds =
        std::env::var("BLOCKCHAIN_RPC_TIMEOUT_S").map_or(Ok(10.0), |v| v.parse::<f64>())?;
    Ok(std::time::Duration::try_from_secs_f64(seconds)?)
}

fn merge<T>(current: &mut Option<T>, value: Option<T>) {
    if value.is_some() {
        *current = value;
    }
}

fn secret_key(key: &str) -> Option<SecretKey> {
    let raw = key
        .strip_prefix("0x")
        .or_else(|| key.strip_prefix("0X"))
        .unwrap_or(key);
    let mut bytes = Zeroizing::new([0u8; 32]);
    let mut padded = Zeroizing::new([b'0'; 64]);
    let digits = match raw.len() {
        63 => {
            padded[1..].copy_from_slice(raw.as_bytes());
            padded.as_slice()
        }
        64 => raw.as_bytes(),
        _ => return None,
    };
    HEXLOWER_PERMISSIVE
        .decode_mut(digits, bytes.as_mut())
        .ok()?;
    SecretKey::from_slice(bytes.as_slice()).ok()
}

fn address(key: &str) -> Option<String> {
    let key = secret_key(key)?;
    Some(crate::managed_wallet::ethereum_address(
        key.public_key().to_encoded_point(false).as_bytes(),
    ))
}

impl Configuration {
    fn view(&self) -> View {
        let v = &self.values;
        let enabled = v.enabled.unwrap_or(false);
        View {
            enabled,
            rpc_url: v.rpc_url.clone(),
            has_private_key: v.private_key.is_some(),
            signer_address: self.signer_address.clone(),
            identity_contract_address: v.identity_contract_address.clone(),
            policy_contract_address: v.policy_contract_address.clone(),
            group_contract_address: v.group_contract_address.clone(),
            is_configured: enabled
                && v.rpc_url.as_ref().is_some_and(|s| !s.is_empty())
                && v.private_key.as_ref().is_some_and(|s| !s.is_empty())
                && v.identity_contract_address
                    .as_ref()
                    .is_some_and(|s| !s.is_empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn partial_updates_preserve_other_fields_and_never_serialize_the_key() {
        let store = ChainSettings::default();
        assert!(!store.view().await.has_private_key);
        let key = format!("{:064x}", 1);
        let view = store
            .update(Update {
                enabled: Some(true),
                rpc_url: Some("http://localhost".into()),
                identity_contract_address: Some("identity".into()),
                private_key: Some(Zeroizing::new(key.clone())),
                ..Default::default()
            })
            .await;
        assert!(view.is_configured);
        assert_eq!(address(&key[1..]), view.signer_address);
        assert_eq!(
            view.signer_address.as_deref(),
            Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
        );
        assert!(!serde_json::to_string(&view).unwrap().contains(&key));
        let replaced = store
            .update(Update {
                private_key: Some(Zeroizing::new("invalid".into())),
                ..Default::default()
            })
            .await;
        assert!(replaced.has_private_key && replaced.is_configured);
        assert!(replaced.signer_address.is_none());
        assert!(
            !store
                .update(Update {
                    enabled: Some(false),
                    ..Default::default()
                })
                .await
                .is_configured
        );
    }
}
