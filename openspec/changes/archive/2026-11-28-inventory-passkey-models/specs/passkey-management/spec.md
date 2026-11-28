## ADDED Requirements

### Requirement: Inventory authenticator models before migration
The operator tooling SHALL report counts of unrevoked credentials grouped by stored AAGUID and credential algorithm in a read-only transaction.

#### Scenario: Inventory an existing deployment
- **WHEN** credentials share a model identifier and algorithm
- **THEN** return their aggregate count, excluding revoked credentials, with missing identifiers represented as null

#### Scenario: No active credentials
- **WHEN** all credentials are revoked or the table is empty
- **THEN** return an empty JSON array
