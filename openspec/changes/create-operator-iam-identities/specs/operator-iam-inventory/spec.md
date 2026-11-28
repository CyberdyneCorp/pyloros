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

#### Scenario: Confirm a chain identity mint

- **WHEN** a mint confirms and its first contract log identifies the assigned token
- **THEN** return HTTP 201 with the stable identity UUID, the full token identifier and the requested identity attributes
- **AND** interpret the token identifier with the same hexadecimal integer syntax as an identity mint retry
- **AND** record one operator audit and return a null user link for the chain identity
- **WHEN** the provider rejects minting or the receipt yields no usable token identifier
- **THEN** return HTTP 404 and omit the creation audit
- **WHEN** PostgreSQL rejects the audit commit after confirmation
- **THEN** return HTTP 500 and retain the confirmed chain effect
