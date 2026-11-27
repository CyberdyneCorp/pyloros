//! Verify an assertion against the challenge and credential loaded by the server.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_cbor_2::Value as Cbor;
use serde_json::Value;
use sha2::{Digest, Sha256};
use webauthn_rs_core::proto::{COSEAlgorithm, COSEKey, PublicKeyCredential};

pub struct StoredCredential<'a> {
    pub id: &'a str,
    pub public_key: &'a [u8],
    pub user_handle: &'a [u8],
    pub counter: u32,
    pub backup_eligible: bool,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AssertionError {
    #[error("invalid passkey assertion")]
    Invalid,
    #[error("authenticator counter did not increase")]
    Counter,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CredentialUsage {
    pub counter: u32,
    pub backed_up: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientData {
    #[serde(rename = "type")]
    ceremony: String,
    challenge: String,
    origin: String,
    #[serde(default)]
    cross_origin: bool,
    token_binding: Option<Value>,
}

impl ClientData {
    fn matches(&self, origin: &str, challenge: &[u8]) -> bool {
        let binding_ok = match &self.token_binding {
            Some(Value::Object(binding)) => matches!(
                binding.get("status").and_then(Value::as_str),
                Some("present" | "supported")
            ),
            _ => true,
        };
        self.ceremony == "webauthn.get"
            && self.origin == origin
            && !self.cross_origin
            && binding_ok
            && URL_SAFE_NO_PAD
                .decode(self.challenge.trim_end_matches('='))
                .is_ok_and(|v| v == challenge)
    }
}

fn check_optional_data(mut tail: &[u8], flags: u8) -> Option<()> {
    if flags & 0x40 != 0 {
        let length = u16::from_be_bytes(tail.get(16..18)?.try_into().ok()?);
        let bytes = tail.get(18 + usize::from(length)..)?;
        let mut decoder = serde_cbor_2::Deserializer::from_slice(bytes);
        Cbor::deserialize(&mut decoder).ok()?;
        tail = bytes.get(decoder.byte_offset()..)?;
    }
    if flags & 0x80 != 0 {
        serde_cbor_2::from_slice::<Cbor>(tail).ok()?;
    } else if !tail.is_empty() {
        return None;
    }
    Some(())
}

pub fn verify(
    rp: &str,
    origin: &str,
    challenge: &[u8],
    stored: &StoredCredential<'_>,
    input: Value,
) -> Result<CredentialUsage, AssertionError> {
    use AssertionError::Invalid;
    let proof: PublicKeyCredential = serde_json::from_value(input).map_err(|_| Invalid)?;
    if proof.type_ != "public-key"
        || proof.id != stored.id
        || URL_SAFE_NO_PAD.encode(&proof.raw_id) != proof.id
        || proof.response.user_handle.as_deref() != Some(stored.user_handle)
    {
        return Err(Invalid);
    }
    let response = proof.response;
    let client: ClientData =
        serde_json::from_slice(&response.client_data_json).map_err(|_| Invalid)?;
    if !client.matches(origin, challenge) {
        return Err(Invalid);
    }
    let signed = &response.authenticator_data;
    let prefix = signed.first_chunk::<37>().ok_or(Invalid)?;
    let flags = prefix[32];
    let eligible = flags & 8 != 0;
    let backed_up = flags & 16 != 0;
    if prefix[..32] != Sha256::digest(rp)[..]
        || flags & 5 != 5
        || eligible != stored.backup_eligible
        || (backed_up && !eligible)
    {
        return Err(Invalid);
    }
    check_optional_data(&signed[37..], flags).ok_or(Invalid)?;
    let counter = u32::from_be_bytes(prefix[33..].try_into().map_err(|_| Invalid)?);
    let cbor: Cbor = serde_cbor_2::from_slice(stored.public_key).map_err(|_| Invalid)?;
    let key = COSEKey::try_from(&cbor).map_err(|_| Invalid)?;
    if !matches!(key.type_, COSEAlgorithm::ES256 | COSEAlgorithm::RS256) {
        return Err(Invalid);
    }
    let mut message = response.authenticator_data;
    message.extend_from_slice(&Sha256::digest(&response.client_data_json));
    if !key
        .verify_signature(&response.signature, &message)
        .unwrap_or(false)
    {
        return Err(Invalid);
    }
    if !eligible && counter > 0 && counter <= stored.counter {
        return Err(AssertionError::Counter);
    }
    Ok(CredentialUsage {
        counter: counter.max(stored.counter),
        backed_up,
    })
}
