## ADDED Requirements

### Requirement: Delegated permission discovery
A registered active service client SHALL be able to read its own ordered permission catalog with a bearer token granting `roles:manage`. The service SHALL apply the configured token revocation policy.

#### Scenario: Read a catalog
- **WHEN** an authorized client requests `GET /api/v1/clients/me/permissions`
- **THEN** return its client identifier and permissions ordered by key, including description and creation time

#### Scenario: Ignore a requested owner
- **WHEN** a caller supplies another client identifier as a query parameter
- **THEN** return only the authenticated client's permissions

#### Scenario: Reject insufficient authorization
- **WHEN** a live service token lacks the required scope
- **THEN** return HTTP 403

#### Scenario: Require service credentials
- **WHEN** the bearer credential is missing, invalid, belongs to a user or identifies a disabled client
- **THEN** return HTTP 401 with a Bearer challenge

#### Scenario: Invalid IAM provider signer
- **WHEN** an authorized catalog read resolves a configured provider with an invalid signer
- **THEN** return the unhandled server error response before catalog lookup
