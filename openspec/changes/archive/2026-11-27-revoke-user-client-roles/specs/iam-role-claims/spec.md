## ADDED Requirements

### Requirement: Revoke a user client role

An operator SHALL be able to revoke one user assignment from a PostgreSQL role. A scoped revocation SHALL work after organization membership ends and SHALL preserve the global assignment. Successful removal, audit and subscribed webhook deliveries SHALL commit atomically.

#### Scenario: Organization group absent

- **WHEN** the global catalog role exists but the requested organization group has never existed
- **THEN** return an empty success, audit the operation and omit event delivery

#### Scenario: Repeat an existing group revocation

- **WHEN** an operator repeats revocation for an existing group and user identity
- **THEN** return an empty success and emit the subscribed role-revoked event
