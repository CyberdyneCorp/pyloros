## ADDED Requirements

### Requirement: Enroll a discoverable credential

The service SHALL let a recently authenticated account enroll a discoverable, user-verified credential from an approved browser or native origin.

#### Scenario: Start enrollment

- **WHEN** a signed-in client begins enrollment
- **THEN** issue fresh creation options with a stable opaque account handle and exclude active credentials for this account and relying party. Bind the expiring challenge to the client, account, session and relying-party configuration.

#### Scenario: Finish enrollment after a backend switch

- **WHEN** the same client submits a valid proof to either backend for an enrollment started on the other
- **THEN** verify the proof and atomically store the credential and its enrollment audit event. Return credential metadata that the existing frontend can display.

#### Scenario: Reuse a submitted challenge

- **WHEN** matching requests submit proofs for the same challenge
- **THEN** only one request can claim it, including when the claimed proof subsequently fails verification.

#### Scenario: Oversized enrollment request

- **WHEN** the body of a passkey request exceeds 65536 bytes
- **THEN** return HTTP 413 before dispatching the request or creating enrollment state.

#### Scenario: Apple anonymous attestation

- **WHEN** a client submits Apple anonymous attestation
- **THEN** verify its nonce and credential public key and require a certificate path valid at verification time under the Apple WebAuthn root.
