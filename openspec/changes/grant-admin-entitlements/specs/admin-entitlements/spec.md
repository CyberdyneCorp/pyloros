## ADDED Requirements

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
