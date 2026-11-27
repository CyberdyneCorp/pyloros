## ADDED Requirements

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
