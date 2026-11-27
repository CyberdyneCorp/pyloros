## ADDED Requirements

### Requirement: Inspect an organization

An operator SHALL be able to retrieve an individual organization's directory record by identifier, including its active status, metadata and timestamps.

#### Scenario: Inactive organization

- **WHEN** an operator retrieves a deactivated organization
- **THEN** return its directory record with the inactive status

#### Scenario: Unknown organization

- **WHEN** an operator requests an identifier with no directory record
- **THEN** return HTTP 404
