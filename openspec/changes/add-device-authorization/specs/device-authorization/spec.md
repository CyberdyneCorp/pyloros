## ADDED Requirements

### Requirement: Start device authorization

The issuer SHALL allow eligible registered clients to request device authorization when the device grant is enabled.

#### Scenario: Start a device session

- **WHEN** a client authenticates and requests an allowed scope set
- **THEN** return a polling credential, human-entered code, verification links, lifetime and polling interval, persist the pending request, and audit the outcome.

#### Scenario: Reject an ineligible request

- **WHEN** credentials, registration policy, scopes, resource indicators or quota prevent issuance
- **THEN** return the applicable OAuth error and record the refusal.

### Requirement: Browser decision and device exchange

The issuer SHALL accept a signed-in user’s decision and allow the requesting client to poll for the result across backend versions.

#### Scenario: Authorize a device

- **WHEN** a user approves a pending code and its client redeems it
- **THEN** issue credentials for the approving user with their authentication context and consume the grant once.

#### Scenario: A device polls before approval or after denial

- **WHEN** the authorization is pending, polled too frequently, expired or denied
- **THEN** return the corresponding polling response and persist any required interval change.
