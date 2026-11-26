## Purpose

Retain a user's grant context across refresh and issuer migration.

## ADDED Requirements

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
