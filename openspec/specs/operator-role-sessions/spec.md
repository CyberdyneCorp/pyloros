# operator-role-sessions Specification

## Purpose
Show operators which identities hold active sessions for a selected IAM role and when those sessions expire.

## Requirements

### Requirement: List active sessions for an IAM role

An authorized operator SHALL be able to retrieve the active sessions for one role from the selected IAM provider.

#### Scenario: Active sessions

- **WHEN** the selected role has active, unexpired sessions
- **THEN** return their session, role and identity identifiers, start and expiry times, active flags and a total equal to the number returned

#### Scenario: Empty session inventory

- **WHEN** the role exists and the provider reports no current sessions
- **THEN** return an empty list and a total of zero

#### Scenario: Unknown role

- **WHEN** the selected provider has no role with the requested identifier
- **THEN** report that the role was not found

### Requirement: Revoke an IAM role session

An authorized operator SHALL be able to revoke a role session known to the configured provider.

#### Scenario: Revoke a session

- **WHEN** the operator revokes a stored session
- **THEN** mark it inactive and record the operator action atomically
- **AND** subsequent inventories and access decisions exclude that session

#### Scenario: Repeated request

- **WHEN** the operator revokes an expired or previously revoked session that still exists
- **THEN** acknowledge the request and record the operator action

#### Scenario: Unknown session

- **WHEN** the selected provider cannot resolve the session
- **THEN** report that the session was not found

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
