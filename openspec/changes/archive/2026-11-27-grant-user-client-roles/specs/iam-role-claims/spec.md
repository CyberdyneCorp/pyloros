## ADDED Requirements

### Requirement: Grant a client role to a user

An operator SHALL be able to grant a global or organization-scoped catalog role to a PostgreSQL user. A scoped grant SHALL require active organization membership. Repeated grants SHALL preserve a single membership and record each successful operation.

#### Scenario: First assignment

- **WHEN** a target has no PostgreSQL IAM identity
- **THEN** create the identity with the membership and audit both actions atomically

#### Scenario: Subscribed role grant

- **WHEN** an active webhook subscription includes role grants and webhooks are enabled
- **THEN** persist a delivery containing the target user, client, role and optional organization in the assignment transaction
