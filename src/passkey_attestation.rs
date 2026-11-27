//! Validate registration against a claimed challenge and project the attested key into shared storage.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use webauthn_rs_core::{
    WebauthnCore,
    internals::AuthenticatorData,
    proto::{RegisterPublicKeyCredential, Registration, RegistrationState},
};

pub struct RegisteredKey {
    pub credential_id: String,
    pub cose_key: Vec<u8>,
    pub algorithm: i32,
    pub counter: u32,
    pub backup_eligible: bool,
    pub backed_up: bool,
    pub aaguid: Uuid,
    pub transports: Value,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid passkey registration")]
pub struct InvalidRegistration;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attestation<'a> {
    fmt: &'a str,
    att_stmt: Cbor,
    auth_data: &'a [u8],
}

pub fn verify(
    rp: &str,
    origin: &str,
    challenge: &[u8],
    input: Value,
) -> Result<RegisteredKey, InvalidRegistration> {
    let proof: RegisterPublicKeyCredential =
        serde_json::from_value(input).map_err(|_| InvalidRegistration)?;
    if proof.type_ != "public-key" || proof.id != URL_SAFE_NO_PAD.encode(&proof.raw_id) {
        return Err(InvalidRegistration);
    }
    // Compare the exact configured origin before the verifier parses and normalizes its URL.
    let client: Value = serde_json::from_slice(&proof.response.client_data_json)
        .map_err(|_| InvalidRegistration)?;
    if client.get("origin").and_then(Value::as_str) != Some(origin) {
        return Err(InvalidRegistration);
    }
    let attestation: Attestation = serde_cbor_2::from_slice(&proof.response.attestation_object)
        .map_err(|_| InvalidRegistration)?;
    // These formats need vendor trust anchors that the generic attestation verifier
    // does not enforce when constructed without an attestation CA list.
    if matches!(
        attestation.fmt,
        "apple" | "android-key" | "android-safetynet"
    ) {
        return Err(InvalidRegistration);
    }
    if attestation.fmt == "none"
        && !matches!(&attestation.att_stmt, Cbor::Map(entries) if entries.is_empty())
    {
        return Err(InvalidRegistration);
    }
    let origin = Url::parse(origin).map_err(|_| InvalidRegistration)?;
    let verifier = WebauthnCore::new_unsafe_experts_only(
        rp,
        rp,
        vec![origin],
        Duration::from_secs(300),
        Some(false),
        Some(false),
    );
    // Reconstruct only server-issued state. The PostgreSQL deadline is checked at claim time.
    let state: RegistrationState = serde_json::from_value(json!({
        "policy":"required","exclude_credentials":[],"challenge":URL_SAFE_NO_PAD.encode(challenge),
        "credential_algorithms":["ES256","RS256"],"require_resident_key":true,
        "authenticator_attachment":null,"extensions":{},"allow_synchronised_authenticators":true
    }))
    .map_err(|_| InvalidRegistration)?;
    let verified = verifier
        .register_credential(&proof, &state, None)
        .map_err(|_| InvalidRegistration)?;
    let data = AuthenticatorData::<Registration>::try_from(attestation.auth_data)
        .map_err(|_| InvalidRegistration)?;
    let key = data.acd.ok_or(InvalidRegistration)?;
    if verified.cred_id != proof.raw_id
        || !data.user_present
        || !verified.user_verified
        || (verified.backup_state && !verified.backup_eligible)
    {
        return Err(InvalidRegistration);
    }
    Ok(RegisteredKey {
        credential_id: URL_SAFE_NO_PAD.encode(&verified.cred_id),
        cose_key: serde_cbor_2::to_vec(&key.credential_pk).map_err(|_| InvalidRegistration)?,
        algorithm: verified.cred.type_ as i32,
        counter: verified.counter,
        backup_eligible: verified.backup_eligible,
        backed_up: verified.backup_state,
        aaguid: Uuid::from_bytes(key.aaguid),
        transports: json!(proof.response.transports.unwrap_or_default()),
    })
}
