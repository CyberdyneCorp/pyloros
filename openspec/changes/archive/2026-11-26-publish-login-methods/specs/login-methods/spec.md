## Purpose

Tell the shared login page which sign-in choices its current deployment supports.

## ADDED Requirements

### Requirement: OAuth provider discovery
GET /api/v1/auth/oauth/providers SHALL return the configured provider names in sorted order in a providers array without requiring a session.

#### Scenario: Multiple providers
- **WHEN** Google and Microsoft have configured client credentials
- **THEN** the list contains google followed by microsoft

#### Scenario: No providers
- **WHEN** neither provider is configured and development stubs are disabled
- **THEN** the list is empty

### Requirement: Passkey discovery
GET /api/v1/auth/passkeys/capabilities SHALL publish the deployment's enabled flag and relying-party identifier without requiring a session.

#### Scenario: Disabled passkeys
- **WHEN** passkeys are disabled
- **THEN** enabled is false and rp_id is null

#### Scenario: Enabled passkeys
- **WHEN** a deployment enables passkeys with a valid relying-party configuration
- **THEN** enabled is true and rp_id contains the configured hostname

### Requirement: Login metadata HTTP methods
The login metadata routes SHALL accept GET. Unsupported methods reaching the route SHALL receive a 405 response with GET in the Allow header.

#### Scenario: HEAD request
- **WHEN** a client sends HEAD to a login metadata route
- **THEN** the server returns 405 with an empty response body
