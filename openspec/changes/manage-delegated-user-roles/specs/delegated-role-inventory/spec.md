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

#### Scenario: Confirm a chain-backed role assignment change

- **WHEN** an authorized operator or delegated client grants or revokes a role backed by a group contract
- **THEN** wait for a successful receipt for the selected group and identity before committing the assignment audit and subscribed deliveries
- **AND** a scoped grant creates its group when needed, while revoking a missing scoped group records the request without emitting a role event
- **AND** return HTTP 500 if PostgreSQL rejects the commit after the contract confirms the change
