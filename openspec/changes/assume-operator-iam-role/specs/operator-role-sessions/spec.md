## ADDED Requirements

### Requirement: Assume an IAM role

An authorized operator SHALL be able to request a role session for an identity with a duration bounded by the selected role's maximum.

#### Scenario: Session issued

- **WHEN** the provider accepts the request
- **THEN** return the session identifier, role, identity, start, expiry and active state
- **AND** commit the session and operator audit together on PostgreSQL

#### Scenario: Duration exceeds maximum

- **WHEN** the requested duration exceeds the role's configured limit
- **THEN** report the limit and refuse the request

#### Scenario: Session visibility

- **WHEN** an issued session is active and its expiry is in the future
- **THEN** include it in the role inventory and apply the role's policies to access evaluation
