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

### Requirement: Edit own phone
PATCH /api/v1/users/me SHALL accept a first-party user credential and a JSON object with an optional nullable phone string. Supplying a string SHALL clear phone verification. An empty string SHALL remove the phone. The response SHALL include the current profile with null role fields.

#### Scenario: Phone changes
- **WHEN** the stored phone changes
- **THEN** the service commits the edit and a subject rectification audit event together, recording the field name without its value

#### Scenario: No phone supplied
- **WHEN** the phone is absent or null
- **THEN** the service preserves the phone and its verification state

#### Scenario: OAuth client credential
- **WHEN** a client-bound access credential is presented
- **THEN** the service returns the unauthenticated challenge

### Requirement: Verify account email
A caller SHALL be able to verify an account email by presenting an unused, unexpired verification credential without signing in.

#### Scenario: Confirm email ownership
- **WHEN** the caller supplies a valid credential
- **THEN** mark the email verified, consume the credential, record the outcome and return an empty 204. An unaffiliated account joins the active organization matching its email domain, including a membership row.

#### Scenario: Invalid or expired credential
- **WHEN** the credential is unknown, expired or previously consumed
- **THEN** return the same 400 error and audit the refusal without altering the account.

#### Scenario: Concurrent use
- **WHEN** multiple callers present the same credential concurrently
- **THEN** at most one verification succeeds.

### Requirement: Profile edit input compatibility

The service SHALL process profile update requests in UTF-8, UTF-16 and UTF-32. Invalid encodings and malformed JSON SHALL return request errors before account access checks.

#### Scenario: Invalid field type

- **WHEN** an authenticated user submits a non-string, non-null phone
- **THEN** return a validation error identifying the field and its submitted value.

#### Scenario: Unrelated profile fields

- **WHEN** an authenticated user submits a valid object containing only unrelated fields
- **THEN** return the current profile with the stored phone and verification state intact.

#### Scenario: Overlapping edits

- **WHEN** two requests both read the old phone before either writes the same new phone
- **THEN** each committed edit records a rectification event. A later sequential request setting the stored value adds no event.

#### Scenario: Plain-text request produces an unhandled error

- **WHEN** an authenticated profile edit receives a plain-text body
- **THEN** return HTTP 500 with the unhandled-error headers specified by the shared HTTP response policy.
