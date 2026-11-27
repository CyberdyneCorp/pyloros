## ADDED Requirements

### Requirement: Revoke client-owned credentials

Pyloros SHALL support the existing form-based OAuth token revocation endpoint and enforce its effects across services sharing the same PostgreSQL deployment.

#### Scenario: Revoke a refresh credential

- **WHEN** the authenticated client presents its refresh token
- **THEN** revoke the associated session and refresh family and return an empty HTTP 200 response with cache prevention headers.

#### Scenario: Revoke a user or service access token

- **WHEN** the authenticated client presents its access token
- **THEN** record the token identifier as revoked through its expiration and preserve other credentials that remain valid.

#### Scenario: Protect token ownership

- **WHEN** a client submits an unknown, expired, first-party or foreign credential
- **THEN** return the same empty success response without revoking another identity's credentials.

#### Scenario: Reject unsupported tokens and unauthorized callers

- **WHEN** the client credentials are invalid, a quota is exhausted, the token parameter is missing or a verified token has an unsupported purpose
- **THEN** return the corresponding OAuth error and preserve the stored credentials.
