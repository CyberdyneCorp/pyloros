## ADDED Requirements

### Requirement: Remove organization membership

An operator SHALL be able to remove a user's membership in an existing organization, clear its primary assignment when applicable and revoke roles bound to that organization.

#### Scenario: Leave primary organization

- **WHEN** an operator removes a membership matching the user's primary organization
- **THEN** clear the primary assignment, remove the membership, revoke the organization's scoped roles and audit the revoked roles

#### Scenario: Remove stale assignment

- **WHEN** a role bound to the target organization survives without a membership record
- **THEN** revoke that role and retain global roles and assignments in other organizations

#### Scenario: Repeated removal

- **WHEN** the user and organization exist and the user has already left the organization
- **THEN** return an empty successful response and record the action

#### Scenario: Local transaction fails

- **WHEN** a required role revocation or operator audit fails
- **THEN** roll back the local membership, primary and role changes

#### Scenario: Concurrent removal

- **WHEN** a repeated request waits for an earlier removal to commit
- **THEN** audit both accepted requests and preserve the user revision when the primary assignment has already been cleared

#### Scenario: Audit serialization

- **WHEN** an accepted action waits for a concurrent audit writer
- **THEN** preserve the action's recording time while linking its hash to the preceding committed audit record

#### Scenario: Remove membership with PostgreSQL role hooks

- **WHEN** removal revokes roles in PostgreSQL and every active revocation hook has a component binding
- **THEN** execute each hook once per revoked role with the event type, user ID, client ID, role key and organization ID. A successful retry records an empty revocation list and dispatches no further callbacks.

#### Scenario: Partial role hook bindings

- **WHEN** the Rust backend receives a PostgreSQL membership removal that would revoke roles and only some active revocation hooks have bindings
- **THEN** return HTTP 503 and preserve the primary organization, memberships and role assignments. Record no removal audit or hook deliveries.
