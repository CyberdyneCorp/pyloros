//! Validate registration against a claimed challenge and project the attested key into shared storage.
mod android;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};
use std::{
    sync::LazyLock,
    time::{Duration, SystemTime},
};
use url::Url;
use uuid::Uuid;
use webauthn_rs_core::{
    WebauthnCore,
    attestation::verify_attestation_ca_chain,
    internals::AuthenticatorData,
    proto::{AttestationCaList, RegisterPublicKeyCredential, Registration, RegistrationState},
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

// Published by Apple at https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
static APPLE_ROOT: LazyLock<AttestationCaList> = LazyLock::new(|| {
    AttestationCaList::try_from(include_bytes!("attestation_roots/apple-webauthn.pem").as_slice())
        .expect("bundled Apple WebAuthn root must parse")
});

pub fn verify(
    rp: &str,
    origin: &str,
    challenge: &[u8],
    input: Value,
) -> Result<RegisteredKey, InvalidRegistration> {
    verify_at(rp, origin, challenge, input, SystemTime::now())
}

fn verify_at(
    rp: &str,
    origin: &str,
    challenge: &[u8],
    input: Value,
    now: SystemTime,
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
    // SafetyNet has a separate signed response and trust path.
    if attestation.fmt == "android-safetynet" {
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
    let android_root;
    let root = match attestation.fmt {
        "apple" => Some(&*APPLE_ROOT),
        "android-key" => {
            android_root = android::hardware_root(&attestation.att_stmt)?;
            Some(&android_root)
        }
        _ => None,
    };
    if let Some(root) = root {
        verify_attestation_ca_chain(&verified.attestation.data, root, now)
            .map_err(|_| InvalidRegistration)?
            .ok_or(InvalidRegistration)?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixel_registration_requires_a_valid_hardware_chain() {
        let proof: Value =
            serde_json::from_str(include_str!("../tests/fixtures/android-pixel-8a.json")).unwrap();
        let challenge = URL_SAFE_NO_PAD
            .decode("t4LWI0iYJSTWPl9WXUdNhdHAnrPDLF9eWAP9lHgmHP8")
            .unwrap();
        let captured = SystemTime::UNIX_EPOCH + Duration::from_secs(1736294400);
        let verify = |time, value| {
            verify_at(
                "localhost",
                "http://localhost:8000",
                &challenge,
                value,
                time,
            )
        };
        let enrolled = verify(captured, proof.clone()).unwrap();
        assert_eq!(enrolled.credential_id, proof["id"]);
        assert_eq!(enrolled.algorithm, -7);
        assert_eq!(
            enrolled.aaguid,
            Uuid::parse_str("b93fd961-f2e6-462f-b122-82002247de78").unwrap()
        );
        assert_eq!(enrolled.counter, 0);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(enrolled.cose_key),
            "pQECAyYgASFYINdWLf6f6sGys_cDg-P0_x7o82Hd410Lfw9oWIJnIxZ1IlggRUDo9sTr3zk9JQMNyeTcqeenJzron8cU67-B66qJa0A"
        );
        for remove in [1, 4] {
            let mut changed = proof.clone();
            let object = &mut changed["response"]["attestationObject"];
            let bytes = URL_SAFE_NO_PAD.decode(object.as_str().unwrap()).unwrap();
            let mut fields: std::collections::BTreeMap<String, Cbor> =
                serde_cbor_2::from_slice(&bytes).unwrap();
            let Some(Cbor::Map(statement)) = fields.get_mut("attStmt") else {
                panic!("expected statement")
            };
            let Some(Cbor::Array(chain)) = statement.get_mut(&Cbor::Text("x5c".into())) else {
                panic!("expected chain")
            };
            assert_eq!(chain.len(), 5);
            chain.remove(remove);
            *object = URL_SAFE_NO_PAD
                .encode(serde_cbor_2::to_vec(&fields).unwrap())
                .into();
            assert!(verify(captured, changed).is_err());
        }
        assert!(verify(captured + Duration::from_secs(86400 * 365), proof).is_err());
    }

    #[test]
    fn touch_id_requires_a_valid_apple_certificate_at_registration_time() {
        // Hardware capture from webauthn-rs-core 0.6.2, test_touchid_attest_apple_anonymous.
        let proof: Value =
            serde_json::from_str(include_str!("../tests/fixtures/apple-touch-id.json")).unwrap();
        let challenge = URL_SAFE_NO_PAD
            .decode("JTbk7yekIKOZQwwdGW7NeDIfxrYK0PvuYxsue--G9NI")
            .unwrap();
        let captured = SystemTime::UNIX_EPOCH + Duration::from_secs(1607398035);
        let verify = |time, value| {
            verify_at(
                "spectral.local",
                "https://spectral.local:8443",
                &challenge,
                value,
                time,
            )
        };
        let enrolled = verify(captured, proof.clone()).unwrap();
        assert_eq!(enrolled.credential_id, proof["id"]);
        assert_eq!(enrolled.algorithm, -7);
        assert!(verify(captured + Duration::from_secs(86400 * 365), proof.clone()).is_err());
        let mut missing_intermediate = proof.clone();
        let object = &mut missing_intermediate["response"]["attestationObject"];
        let bytes = URL_SAFE_NO_PAD.decode(object.as_str().unwrap()).unwrap();
        let mut fields: std::collections::BTreeMap<String, Cbor> =
            serde_cbor_2::from_slice(&bytes).unwrap();
        let Some(Cbor::Map(statement)) = fields.get_mut("attStmt") else {
            panic!("expected statement")
        };
        let Some(Cbor::Array(chain)) = statement.get_mut(&Cbor::Text("x5c".into())) else {
            panic!("expected certificate chain")
        };
        assert_eq!(chain.len(), 2);
        chain.truncate(1);
        *object = URL_SAFE_NO_PAD
            .encode(serde_cbor_2::to_vec(&fields).unwrap())
            .into();
        assert!(verify(captured, missing_intermediate).is_err());

        let mut modified = proof;
        let client = &mut modified["response"]["clientDataJSON"];
        let mut bytes = URL_SAFE_NO_PAD.decode(client.as_str().unwrap()).unwrap();
        bytes.push(b' ');
        *client = URL_SAFE_NO_PAD.encode(bytes).into();
        assert!(verify(captured, modified).is_err());
    }
}
