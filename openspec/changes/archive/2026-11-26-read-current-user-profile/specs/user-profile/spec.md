## Purpose

Allow applications and the shared frontend to read the account represented by a user access credential.

## ADDED Requirements

### Requirement: Current user profile
GET /api/v1/users/me SHALL authenticate user access tokens from the bearer header or access cookie and return the current account, effective administrator status, primary organization, entitlements and live role assignments. An explicit bearer credential SHALL take precedence. Dynamic-client tokens SHALL be refused.

#### Scenario: Missing credential
- **WHEN** no credential is supplied
- **THEN** the endpoint returns 401 with the bearer and access-cookie challenge

#### Scenario: Revocation enforcement
- **WHEN** enforcement is enabled and a verified token is denylisted, belongs to a revoked session or falls at or before the user's issuance cutoff
- **THEN** the endpoint returns 401

#### Scenario: Unavailable roles
- **WHEN** the account exists and the IAM lookup is unavailable
- **THEN** the profile contains null global and organization role fields
