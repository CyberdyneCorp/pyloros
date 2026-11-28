# delegated-role-inventory Specification

## Purpose

Allow a service client to discover the roles it manages and inspect the permissions assigned to each role.

## Requirements

### Requirement: Service-client role discovery
An active service client with a valid bearer granting `roles:manage` SHALL be able to read its own role inventory and role-permission mappings.

#### Scenario: List roles
- **WHEN** the service requests `GET /api/v1/clients/me/roles`
- **THEN** return the calling client identifier and its global roles with their keys, descriptions and member counts

#### Scenario: Inspect the permissions for a role
- **WHEN** the service requests `GET /api/v1/clients/me/roles/{role_key}/permissions` for an existing role
- **THEN** return the calling client's identifier, role key and ordered permission keys

#### Scenario: Unknown role
- **WHEN** a valid role key is absent from the calling client's active role provider
- **THEN** return HTTP 404

#### Scenario: Provider outage
- **WHEN** a valid role lookup needs an unavailable runtime IAM chain
- **THEN** return HTTP 503

### Requirement: Read a user's roles for a service client
An active service client with a valid bearer granting `roles:manage` SHALL be able to retrieve a user's current roles for that client.

#### Scenario: Read global and organization roles
- **WHEN** the caller requests `GET /api/v1/clients/me/users/{user_id}/roles` for an existing user
- **THEN** return the user identifier and the client's sorted global role keys, plus organization roles for active memberships when present

#### Scenario: No eligible assignments
- **WHEN** the user has no eligible assignments for the calling client
- **THEN** return an empty roles array and omit the organization roles field

#### Scenario: Unknown user
- **WHEN** the authenticated client requests an unknown user identifier
- **THEN** return HTTP 404

### Requirement: Decode numeric values in role grant documents
Operator and delegated user role grants SHALL apply the IAM document rules before checking credentials. Unused non-finite numeric fields SHALL be ignored after parsing. An integer exceeding 4,300 decimal digits SHALL produce HTTP 400 before a grant is recorded.

#### Scenario: Extra numeric metadata
- **WHEN** an authorized caller submits a valid assignment and an unrelated field containing a non-finite numeric literal
- **THEN** grant the role using the supplied assignment fields

#### Scenario: Invalid assignment field
- **WHEN** a field validation error would include a non-finite number in the response
- **THEN** return the unhandled HTTP 500 response and leave the assignment unchanged

### Requirement: Measure registered role namespace overlap
An operator SHALL be able to count registered client ID pairs where the longer ID starts with the shorter nonempty ID followed by a colon. The report SHALL return only aggregate counts from a read-only database snapshot.

#### Scenario: Nested identifiers
- **WHEN** three registrations form a chain of colon-delimited prefixes
- **THEN** count all three distinct shorter–longer pairs, including the pair spanning two separators
- **AND** report the numbers of distinct shorter and longer identifiers

#### Scenario: Inactive registration
- **WHEN** either member of an overlapping pair is inactive
- **THEN** include the pair in the total and exclude it from the active-pair count
