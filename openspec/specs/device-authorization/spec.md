# device-authorization Specification

## Purpose

Allow a device client to obtain credentials after its user approves the request in a signed-in browser. Persist authorization and polling state so clients can continue across issuer upgrades.

## Requirements

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

#### Scenario: Verify a user code in the browser

- **WHEN** a signed-in user opens a pending code
- **THEN** show the requesting client, displayed code and requested scopes using the deployment's shared verification page. The decision ticket binds the form to that user and request.

#### Scenario: Apply the user's decision

- **WHEN** the signed-in user submits a valid approval or denial
- **THEN** persist a single decision, its authentication context and audit event together. An untrusted client's approval also records the user's consent for the displayed scopes.

#### Scenario: Refuse a stale form

- **WHEN** the code has expired, the request already has a decision, or the ticket belongs to a different user
- **THEN** show the corresponding error page and preserve the existing request and consent state.

#### Scenario: A device polls faster than its advertised interval

- **WHEN** the same pending authorization is polled again before its interval elapses
- **THEN** extend the persisted interval by five seconds and report the new interval. Pending and backoff responses do not write a token-grant audit event.

#### Scenario: Competing redemptions

- **WHEN** either issuer receives an approved device code that the other has already redeemed
- **THEN** refuse replay and revoke the session and refresh credentials created by the successful exchange.

#### Scenario: Persistence fails during issuance

- **WHEN** the session, tokens or successful grant audit cannot be persisted together
- **THEN** roll back issuance and leave the approved code available for retry.

### Requirement: Preserve device grant state on unsupported ID-token signing
A device grant that establishes a session under HS256 and requests an ID token SHALL return the signing error and commit its grant state.

#### Scenario: Approved device requests an unsupported ID token
- **WHEN** signing the ID token is unsupported after a session has been issued
- **THEN** record the successful user grant, mark the device code consumed with an empty session binding, and return the OAuth server error
- **AND** subsequent polls refuse replay without issuing another session
