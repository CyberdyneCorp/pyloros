## ADDED Requirements

### Requirement: Include direct user relationships in account downloads
A subject export SHALL include the client, object, relation and account identifiers of direct user relationships. The same row limit and truncation indicator as other export sections SHALL apply.

#### Scenario: Administrator or account holder downloads a populated graph
- **WHEN** an authorized caller exports an account with direct assignments
- **THEN** the download includes only assignments for that account and omits object-to-object relationships

#### Scenario: No applicable relationships
- **WHEN** relationship storage is absent or the account has no direct assignments
- **THEN** the service returns the existing export sections without adding an empty graph section
