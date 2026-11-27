## ADDED Requirements

### Requirement: Replace the permissions assigned to a client role
An active service client with a valid bearer granting `roles:manage` SHALL be able to replace the permissions of its own existing role using its own permission catalog.

#### Scenario: Replace a mapping
- **WHEN** the caller submits valid permission keys to `PUT /api/v1/clients/me/roles/{role_key}/permissions`
- **THEN** return the client identifier, role key and sorted distinct permissions, and record the client as the audit actor

#### Scenario: Clear a mapping
- **WHEN** the caller submits an empty permission list
- **THEN** remove all permissions from that client's role

#### Scenario: Reject unknown permissions
- **WHEN** the requested list includes a key absent from the calling client's catalog
- **THEN** return HTTP 400 and preserve the prior mapping
