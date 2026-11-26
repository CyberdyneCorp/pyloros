## Purpose

Carry a browser authorization grant across requests and issuer upgrades.

## ADDED Requirements

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
