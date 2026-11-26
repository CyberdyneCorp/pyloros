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
An OpenID grant SHALL produce an RS256 ID token whose subject is the granted user and whose audience is the calling client. It SHALL carry issuer, issuance time, expiry, and any recorded nonce and original authentication context. Other grants SHALL omit the ID token.

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
User-grant access tokens SHALL be signed with RS256 and identify the issuer, user, session, unique token, lifetime, calling client and granted scopes. They SHALL include the effective admin flag, active personal and primary-organization entitlements, active memberships, and available role and permission claims. A missing authorization snapshot SHALL omit the unresolved claims. A bound resource SHALL determine the audience and an unregistered bound resource SHALL prevent issuance.

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
