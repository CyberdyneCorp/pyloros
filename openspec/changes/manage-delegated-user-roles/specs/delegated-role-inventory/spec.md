## ADDED Requirements

### Requirement: Manage a user's assignments for the calling client
An active service client with a valid bearer granting `roles:manage` SHALL be able to grant and revoke its own roles for a user. Each successful operation SHALL record the calling client in the audit trail.

#### Scenario: Grant an existing role
- **WHEN** the client grants a global role to an existing user on PostgreSQL
- **THEN** create the user's IAM identity if needed and return HTTP 201 with the assignment

#### Scenario: Grant an organization role
- **WHEN** the client grants a role scoped to an organization
- **THEN** require active membership in that organization

#### Scenario: Revoke an assignment
- **WHEN** the service revokes the user's global or organization-scoped role
- **THEN** remove the selected assignment and return HTTP 204
