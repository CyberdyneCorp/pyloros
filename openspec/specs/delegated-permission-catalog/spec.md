# delegated-permission-catalog Specification

## Purpose

Allow service clients to discover the permissions available for assignment within their own registration.

## Requirements

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

### Requirement: Recover an existing oversized permission catalog
The operator and delegated permission endpoints SHALL expose every stored permission in the authorized client's catalog and allow explicit deletion when the catalog exceeds 256 entries.

#### Scenario: Attempt a creation while full
- **WHEN** the catalog already holds at least 256 keys
- **THEN** return HTTP 409 for creation, identifying an existing key as a duplicate and a new key as exceeding capacity

#### Scenario: Recreate a retired permission
- **WHEN** deletion reduces the catalog below 256 and a caller creates a previously retired key
- **THEN** create the permission and leave its former role assignments removed
