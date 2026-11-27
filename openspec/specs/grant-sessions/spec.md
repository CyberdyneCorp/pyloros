# grant-sessions Specification

## Purpose
Retain a user's grant context across refresh and issuer migration.

## Requirements

### Requirement: Atomic session creation
A successful code grant SHALL create its bound session and initial refresh record in the code claim transaction. Both records SHALL use the signed token's expiry. The session SHALL preserve the original authentication context and store a SHA-256 digest of the refresh token. The refresh record SHALL preserve client, resource and consented scopes.

#### Scenario: Issuance rolls back
- **WHEN** the exchange transaction rolls back after writing session state
- **THEN** the session and refresh record disappear and the code remains available

### Requirement: Refresh credential exposure
The service SHALL sign a refresh JWT containing issuer, user, session ID, unique token ID, token type and issuance and expiry times. It SHALL return the refresh credential to the caller only when the granted scopes include offline_access.

#### Scenario: No offline access
- **WHEN** a code grant carries only the openid scope
- **THEN** the session and refresh records are created and the client receives no refresh credential

### Requirement: Grant identity token
With RSA signing configured, an OpenID grant SHALL produce an RS256 ID token whose subject is the granted user and whose audience is the calling client. It SHALL carry issuer, issuance time, expiry, and any recorded nonce and original authentication context. Other grants SHALL omit the ID token.

#### Scenario: Email and profile consent
- **WHEN** the grant includes email and profile scopes
- **THEN** available email and verification status, display name and profile image appear in the token

#### Scenario: Authorization claims
- **WHEN** the roles scope is granted and role lookup succeeds
- **THEN** the ID token includes unprefixed global and organization roles for the calling client, and includes resolved permission claims when available

#### Scenario: Unresolved roles
- **WHEN** role lookup is unavailable
- **THEN** role and permission fields are absent from the ID token

### Requirement: User access tokens
User-grant access tokens SHALL be signed with the configured session algorithm (RS256 or HS256) and identify the issuer, user, session, unique token, lifetime, calling client and granted scopes. They SHALL include the effective admin flag, active personal and primary-organization entitlements, active memberships, and available role and permission claims. A missing authorization snapshot SHALL omit the unresolved claims. A bound resource SHALL determine the audience and an unregistered bound resource SHALL prevent issuance.

#### Scenario: Organization entitlements
- **WHEN** a user's active primary organization grants a product already granted to the user
- **THEN** the access token contains one entry for that product

#### Scenario: Unbound client
- **WHEN** an unbound grant's client has no default audience
- **THEN** its access token omits the audience field

### Requirement: PostgreSQL token authorization snapshot
The issuer SHALL resolve global and organization-bound client roles from the user's PostgreSQL IAM groups. Only active memberships SHALL contribute organization-bound roles. Permission lists SHALL be sorted, deduplicated and scoped to the calling client's catalog plus active administrator-registered clients sharing the effective audience.

#### Scenario: Shared audience
- **WHEN** an organization-bound role implies a permission in an eligible audience catalog
- **THEN** that permission appears only under the matching organization

#### Scenario: Unavailable IAM
- **WHEN** the IAM group lookup fails
- **THEN** the snapshot is unresolved and the grant transaction remains usable

#### Scenario: No assignments
- **WHEN** the group lookup succeeds for a user with no role assignments
- **THEN** the resolved snapshot contains empty roles and permissions

### Requirement: Assemble a user grant response
The issuer SHALL create the session and assemble a bearer response in the caller's transaction. Both signers SHALL use one authorization snapshot resolved for the access token's effective audience. The response SHALL report the access-token lifetime in seconds and the sorted granted scopes.

#### Scenario: Scoped credentials
- **WHEN** the grant includes openid and offline_access
- **THEN** the response includes an ID token and refresh token alongside the access token

#### Scenario: Access only
- **WHEN** the grant includes neither openid nor offline_access
- **THEN** the response omits both optional credentials

### Requirement: Audit successful authorization code grants
A successful authorization code exchange SHALL record a verifiable token grant event in the session transaction. The event SHALL identify the account, client, session, granted scopes and available request attribution.

#### Scenario: Committed grant
- **WHEN** the session transaction commits
- **THEN** its audit record can be verified from the stored fields

#### Scenario: Rolled back grant
- **WHEN** the session transaction rolls back
- **THEN** its success event is discarded

### Requirement: Authorization code exchange decision
The exchange service SHALL commit a successful issuance before returning credentials. It SHALL commit replay revocations before recording a refusal separately. A refusal SHALL retain its OAuth error and status if the refusal audit write fails.

#### Scenario: Unknown client
- **WHEN** client authentication fails
- **THEN** the response reports invalid_client with status 401 and the refusal has no user attribution

#### Scenario: Matched code
- **WHEN** an authenticated client presents a matching code with an incorrect verifier
- **THEN** the service returns invalid_grant and records the subject from the code

#### Scenario: Removed resource
- **WHEN** a claimed code refers to a resource removed from the registry
- **THEN** the exchange consumes the code and refuses issuance without creating a session

### Requirement: First-party session issuance
After authentication, the service SHALL issue access and refresh credentials for the same active user and session. The access credential SHALL contain the current account authorization and authentication context and omit OAuth client, scope, audience and permission claims. The session and its refresh record SHALL participate in the caller transaction.

#### Scenario: Continue a session on another deployment
- **WHEN** a first-party session commits and the other deployment uses the same issuer, keys and database
- **THEN** it can authenticate the access credential and rotate the refresh credential with the original authentication context

### Requirement: Rotate a first-party refresh token
The browser refresh endpoint SHALL accept a refresh cookie or JSON token, prefer the cookie, and issue a new pair only for a live first-party session belonging to an active account. It SHALL preserve the session identity and original authentication context, reevaluate account claims, and record rotation and activity atomically.

#### Scenario: Concurrent refresh
- **WHEN** multiple requests compete to claim one live token
- **THEN** at most one succeeds and a losing claim returns an authentication error.

#### Scenario: Reuse after rotation
- **WHEN** a replaced credential is reused inside the configured grace interval and its successor exists
- **THEN** reject the request while keeping the session usable.

#### Scenario: Replay outside grace
- **WHEN** an otherwise valid credential for the session is unknown or reused outside grace
- **THEN** revoke the session and its remaining refresh credentials before returning the error.

### Requirement: End a browser session
The single-session logout endpoint SHALL clear browser session cookies and return 204 for a valid request body, including when the credentials are already expired or missing. It SHALL denylist a valid presented access token until expiry and revoke the session family identified by a valid refresh token.

#### Scenario: An existing login ends
- **WHEN** the browser presents its access and refresh cookies
- **THEN** record logoff, revoke the session and its refresh credentials, denylist the access identifier and expire the cookies.

#### Scenario: Credential precedence
- **WHEN** both cookie and explicit credentials are present
- **THEN** use the refresh cookie before the JSON token and the bearer access token before the access cookie.

#### Scenario: Access token alone
- **WHEN** a valid access token is presented without a refresh token
- **THEN** denylist its identifier while leaving the session family available.

### Requirement: Sign out across all sessions
An authenticated first-party caller SHALL be able to revoke every open session of its account. The operation SHALL advance the account’s access-token cutoff, audit the number of newly revoked sessions and clear the current browser cookies.

#### Scenario: Several devices signed in
- **WHEN** the caller signs out everywhere
- **THEN** sessions belonging to that account stop refreshing, older access credentials fail when revocation is enforced, and another account retains access.

#### Scenario: Untrusted caller
- **WHEN** the credential is absent, invalid, or issued to an OAuth client
- **THEN** refuse the operation without changing session state.

### Requirement: First-party session input decoding

The service SHALL decode supported JSON encodings before validating credentials and SHALL preserve submitted values in field errors for sign-in, MFA verification, refresh and logout.

#### Scenario: UTF-16 refresh request

- **WHEN** a UTF-16 JSON document supplies a numeric refresh token
- **THEN** validation identifies the refresh token as an invalid string and returns its submitted value

#### Scenario: Unsupported request media

- **WHEN** a session operation receives a nonempty plain-text or URL-encoded body
- **THEN** it returns the compatible internal error response without issuing credentials

### Requirement: Coordinate logout with account erasure

Account-wide logout SHALL revoke visible sessions before advancing the account cutoff and SHALL commit session revocations, cutoff and audit together.

#### Scenario: Accepted logout overlaps account deletion

- **WHEN** both operations have admitted their callers and contend for the same open session
- **THEN** both operations can complete, the account is erased and its refresh credentials are refused

### Requirement: Distinguish session persistence times

The service SHALL record session creation and initial activity at the PostgreSQL transaction timestamp and timestamp the initial refresh record after the session insert succeeds.

#### Scenario: Delayed session write

- **WHEN** contention delays persistence after the credential issue time
- **THEN** the stored refresh record reflects its registration time and the signed credential retains its original lifetime
