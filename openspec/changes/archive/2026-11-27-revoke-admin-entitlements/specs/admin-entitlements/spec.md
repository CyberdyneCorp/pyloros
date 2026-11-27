## ADDED Requirements

### Requirement: Revoke a product entitlement
Pyloros SHALL let a first-party administrator revoke an existing personal or organization grant and append an audit record in the same transaction.

#### Scenario: Withdraw access
- **WHEN** the administrator deletes a grant
- **THEN** set its status and revocation timestamp, retain the grant history and return HTTP 204

#### Scenario: Revoke again
- **WHEN** the grant was already revoked
- **THEN** refresh its revocation timestamp and record the new administrative action

#### Scenario: Missing grant
- **WHEN** the identifier is valid and the grant does not exist
- **THEN** return HTTP 404
