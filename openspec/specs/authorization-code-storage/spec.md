# authorization-code-storage Specification

## Purpose
Carry a browser authorization grant across requests and issuer upgrades.

## Requirements

### Requirement: Persist grant bindings
The store SHALL persist an opaque code by SHA-256 digest, with client, user, redirect, scopes, S256 challenge, expiry and optional nonce, resource and authentication context. Lookup SHALL require the original code and client.

#### Scenario: Client isolation
- **WHEN** a different client looks up the same code
- **THEN** no grant is returned

### Requirement: Transactional single use
A claim SHALL record consumption and bind the issuing session in the caller's transaction. Exactly one competing transaction may commit the claim.

#### Scenario: Session creation rolls back
- **WHEN** the transaction that claimed the code is rolled back
- **THEN** a subsequent exchange may claim it

#### Scenario: Another transaction wins
- **WHEN** a concurrent successful claim commits
- **THEN** a later claim returns false and a fresh lookup identifies the winning session

### Requirement: Checked redemption
For an authenticated client authorized to use the code grant, the application SHALL verify an unexpired code's exact redirect URI, S256 verifier, optional resource and active user before claiming it. An explicitly requested resource SHALL be a single value matching the stored resource.

#### Scenario: Binding mismatch
- **WHEN** an unused code is presented with an incorrect redirect, verifier or resource
- **THEN** the request is refused and the code remains unused

#### Scenario: Subject disabled
- **WHEN** the user is inactive at redemption
- **THEN** the request is refused and the code remains unused

### Requirement: Replayed exchange
Reuse by the bound client SHALL refuse the exchange and revoke the associated session and its live refresh tokens when one exists. Losing a concurrent claim SHALL use the same replay handling.

#### Scenario: Session family revocation
- **WHEN** the replay refusal commits
- **THEN** the winning session and its remaining refresh tokens have revocation timestamps

### Requirement: Registered client authentication
Before looking up a code, redemption SHALL authenticate an active client and require its authorization_code grant. A public client SHALL proceed to grant validation without a shared secret. A confidential client SHALL prove possession of its current secret or a previous secret whose grace period is still open.

#### Scenario: Rotation deadline
- **WHEN** a confidential client presents only its previous secret at or after its expiry
- **THEN** the service refuses client authentication

#### Scenario: Client cannot use the code grant
- **WHEN** a correctly authenticated client is registered only for client credentials
- **THEN** the service refuses the grant before looking up or consuming a code
