## ADDED Requirements

### Requirement: Create an operator IAM identity

An authorized operator SHALL be able to create an identity using the selected IAM provider and optionally link it to a user in PostgreSQL.

#### Scenario: Create a database identity

- **WHEN** the operator creates an identity with default lifecycle settings
- **THEN** return an active, soulbound identity with HTTP 201 and atomically record its creation audit

#### Scenario: User already has an identity

- **WHEN** the requested user already has an IAM identity in PostgreSQL
- **THEN** return a conflict and preserve the existing identity

#### Scenario: Prepare a chain mint

- **WHEN** identity creation uses the chain provider
- **THEN** encode the owner, public key and metadata URI with an empty email argument
