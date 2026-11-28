## ADDED Requirements

### Requirement: Manage a service client's permission definitions
A service client authenticated for delegated permission discovery SHALL be able to create and delete its own permission definitions. The service SHALL commit each successful change with a hash-linked audit entry identifying the calling client.

#### Scenario: Create a permission
- **WHEN** a scoped caller posts a valid new permission key and optional description to its catalog
- **THEN** return the created definition with HTTP 201

#### Scenario: Duplicate permission
- **WHEN** the caller creates a key already present in its catalog
- **THEN** return HTTP 409

#### Scenario: Delete a permission
- **WHEN** the caller deletes an existing key from its catalog
- **THEN** return HTTP 204 and remove its associated role mappings for this client

#### Scenario: Isolate catalogs
- **WHEN** a caller deletes a key that only exists in another client's catalog
- **THEN** return HTTP 404 and preserve the other client's definition

#### Scenario: Deletion is rejected at commit
- **WHEN** PostgreSQL explicitly rejects the permission deletion at commit
- **THEN** return HTTP 500 and preserve the permission definition, role assignments and audit history
- **AND** a successful retry removes the definition and its role mappings and records the caller once
