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

#### Scenario: PostgreSQL rejects the withdrawal at commit
- **WHEN** PostgreSQL explicitly rejects the transaction revoking the grant
- **THEN** return HTTP 500 and preserve the prior grant, operator audit and component delivery state

### Requirement: Grant product access
Pyloros SHALL allow a first-party administrator to grant an eligible product to one existing user or organization with an optional plan and expiry.

#### Scenario: Create a grant
- **WHEN** the owner has no grant for the requested product and plan
- **THEN** create an active administrative grant and return HTTP 201 with its identity, owner, grantor, token and timestamps
- **AND** record the grant creation in the administrative audit

#### Scenario: Restore a grant
- **WHEN** the owner already has the requested product and plan
- **THEN** retain the grant identity and external reference, set its administrative grantor and requested expiry, and clear any revocation
- **AND** return HTTP 201 and audit the refresh

#### Scenario: PostgreSQL rejects the grant at commit
- **WHEN** PostgreSQL explicitly rejects the transaction creating or refreshing a grant
- **THEN** return HTTP 500 and preserve the prior grant, operator audit and component delivery state
