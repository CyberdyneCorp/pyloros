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
