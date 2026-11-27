use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pyloros::passkey_assertion::{AssertionError, CredentialUsage, StoredCredential, verify};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Fixture {
    id: String,
    key: String,
    handle: String,
    challenge: String,
    eligible: bool,
    #[serde(default)]
    zero: bool,
    proof: Value,
}

#[test]
fn signed_assertions_respect_account_binding_and_counter_policy() {
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/passkey-assertions.json")).unwrap();
    for f in fixtures {
        let public_key = URL_SAFE_NO_PAD.decode(f.key).unwrap();
        let handle = URL_SAFE_NO_PAD.decode(f.handle).unwrap();
        let challenge = URL_SAFE_NO_PAD.decode(f.challenge).unwrap();
        let mut stored = StoredCredential {
            id: &f.id,
            public_key: &public_key,
            user_handle: &handle,
            counter: 1,
            backup_eligible: f.eligible,
        };
        let check = |stored: &StoredCredential, proof: Value| {
            verify(
                "example.test",
                "https://keys.example.test",
                &challenge,
                stored,
                proof,
            )
        };
        assert_eq!(
            check(&stored, f.proof.clone()),
            Ok(CredentialUsage {
                counter: if f.zero { 1 } else { 3 },
                backed_up: f.eligible
            })
        );
        stored.counter = 0;
        assert_eq!(
            check(&stored, f.proof.clone()),
            Ok(CredentialUsage {
                counter: if f.zero { 0 } else { 3 },
                backed_up: f.eligible,
            })
        );
        for previous in [3, 5] {
            stored.counter = previous;
            let expected = if f.eligible || f.zero {
                Ok(CredentialUsage {
                    counter: previous,
                    backed_up: f.eligible,
                })
            } else {
                Err(AssertionError::Counter)
            };
            assert_eq!(check(&stored, f.proof.clone()), expected);
        }
        let mut changed = f.proof.clone();
        changed["response"]["signature"] = "AA".into();
        assert_eq!(check(&stored, changed), Err(AssertionError::Invalid));
        assert_eq!(
            check(
                &StoredCredential {
                    user_handle: b"other",
                    ..stored
                },
                f.proof.clone()
            ),
            Err(AssertionError::Invalid)
        );
        assert_eq!(
            check(
                &StoredCredential {
                    backup_eligible: !f.eligible,
                    ..stored
                },
                f.proof.clone()
            ),
            Err(AssertionError::Invalid)
        );
        assert!(
            verify(
                "example.test",
                "https://other.example.test",
                &challenge,
                &stored,
                f.proof.clone()
            )
            .is_err()
        );
        assert!(
            verify(
                "example.test",
                "https://keys.example.test",
                &[0; 32],
                &stored,
                f.proof.clone()
            )
            .is_err()
        );
        assert!(
            verify(
                "other.test",
                "https://keys.example.test",
                &challenge,
                &stored,
                f.proof
            )
            .is_err()
        );
    }
}
