## ADDED Requirements

### Requirement: Reauthenticate an existing session with a passkey

The service SHALL allow a live first-party session to establish recent authentication with one of its owner's active passkeys.

#### Scenario: Start a session-bound challenge

- **WHEN** an authenticated browser or native client requests reauthentication
- **THEN** bind an expiring challenge to the owner, session, relying party, origin, client binding and policy. Offer only active credentials registered by that owner for the relying party. Respond with HTTP 404 when there are none.

#### Scenario: Prove presence

- **WHEN** the same client and session submit the matching challenge and a valid assertion from an eligible credential
- **THEN** require an enrolled second factor when the account has MFA enabled. Record recent authentication for that session on success and return HTTP 204.

#### Scenario: Replay or change sessions

- **WHEN** a client reuses a consumed challenge or submits it from another session
- **THEN** refuse the request and preserve the existing recent-authentication state.
