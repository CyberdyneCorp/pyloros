# admin-entitlements Specification

## Purpose
Describe administrative reporting on product access granted to users and organizations.

## Requirements

### Requirement: Inspect entitlement records
Pyloros SHALL expose a first-party administrative directory of personal and organization grants and current subscriber statistics.

#### Scenario: Filter the directory
- **WHEN** an operator selects a user, organization or product
- **THEN** return matching grants newest first with the filtered total, owner labels, grantor email, timestamps and access token string

#### Scenario: Inspect subscriber statistics
- **WHEN** an administrator requests subscriber statistics
- **THEN** group active unexpired grants by product, plan and source, resolving the client display name before the virtual product name and falling back to the key
- **AND** sort products by descending total then ascending key

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
