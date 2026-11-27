use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pyloros::passkey_attestation::verify;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Fixture {
    algorithm: i32,
    challenge: String,
    origin: String,
    key: String,
    proof: Value,
}

#[test]
fn verifies_packed_self_attestation_for_each_advertised_algorithm() {
    // Independent synthetic authenticators signed these fixtures with disposable keys.
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/passkey-attestations.json")).unwrap();
    for f in fixtures {
        let challenge = URL_SAFE_NO_PAD.decode(f.challenge).unwrap();
        let check = |rp, origin, challenge: &[u8], proof| verify(rp, origin, challenge, proof);
        let key = check("example.test", &f.origin, &challenge, f.proof.clone()).unwrap();
        assert_eq!(key.algorithm, f.algorithm);
        assert_eq!(URL_SAFE_NO_PAD.encode(key.cose_key), f.key);
        assert_eq!(key.credential_id, f.proof["id"]);
        assert!(check("other.test", &f.origin, &challenge, f.proof.clone()).is_err());
        assert!(
            check(
                "example.test",
                "https://other.test",
                &challenge,
                f.proof.clone()
            )
            .is_err()
        );
        assert!(check("example.test", &f.origin, &[0; 32], f.proof.clone()).is_err());

        // Leading JSON whitespace preserves client-data semantics but changes the signed bytes.
        let mut changed = f.proof;
        let client = &mut changed["response"]["clientDataJSON"];
        let mut bytes = vec![b' '];
        bytes.extend(URL_SAFE_NO_PAD.decode(client.as_str().unwrap()).unwrap());
        *client = URL_SAFE_NO_PAD.encode(bytes).into();
        assert!(check("example.test", &f.origin, &challenge, changed).is_err());
    }
}

#[test]
fn anonymous_attestation_requires_user_presence_and_verification() {
    use serde_cbor_2::Value as Cbor;
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/passkey-attestations.json")).unwrap();
    let f = &fixtures[0];
    let challenge = URL_SAFE_NO_PAD.decode(&f.challenge).unwrap();
    let object = URL_SAFE_NO_PAD
        .decode(f.proof["response"]["attestationObject"].as_str().unwrap())
        .unwrap();
    let Cbor::Map(mut fields) = serde_cbor_2::from_slice(&object).unwrap() else {
        panic!("expected attestation map")
    };
    fields.insert(Cbor::Text("fmt".into()), Cbor::Text("none".into()));
    fields.insert(Cbor::Text("attStmt".into()), Cbor::Map(Default::default()));
    for (flags, valid) in [(0x45, true), (0x44, false), (0x41, false), (0x55, false)] {
        let Some(Cbor::Bytes(data)) = fields.get_mut(&Cbor::Text("authData".into())) else {
            panic!("expected authenticator bytes")
        };
        data[32] = flags;
        let mut proof = f.proof.clone();
        let attestation = serde_cbor_2::to_vec(&Cbor::Map(fields.clone())).unwrap();
        proof["response"]["attestationObject"] = URL_SAFE_NO_PAD.encode(attestation).into();
        assert_eq!(
            verify("example.test", &f.origin, &challenge, proof).is_ok(),
            valid
        );
    }
}
