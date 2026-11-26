# user-profile Specification

## Purpose
Allow applications and the shared frontend to read the account represented by a user access credential.

## Requirements

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

### Requirement: Current user entitlements
GET /api/v1/users/me/entitlements SHALL authenticate the caller under the current-user profile policy and return an entitlements array of sorted, distinct product tokens. Active personal grants and active grants inherited from the active primary organization SHALL contribute. Expired grants SHALL be excluded.

#### Scenario: Personal and organization grants overlap
- **WHEN** the user and the primary organization both hold an active grant for the same product and plan
- **THEN** the product and plan appear once

#### Scenario: No grants
- **WHEN** an authenticated caller has no effective product grants
- **THEN** the endpoint returns an empty array
