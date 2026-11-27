## ADDED Requirements

### Requirement: Create an organization

An operator SHALL be able to create an active organization and obtain its directory record. Creation SHALL validate directory field lengths and string metadata, normalize the stored domain, and atomically record the operator action.

#### Scenario: Directory conflict

- **WHEN** an operator submits a domain in use or a GitHub owner already mapped to an active organization
- **THEN** report a conflict and preserve the existing organization

#### Scenario: Audit failure

- **WHEN** the creation audit fails
- **THEN** roll back the newly inserted organization

#### Scenario: Concurrent organizations with the same name

- **WHEN** operators create organizations with the same display name and distinct mappings
- **THEN** retain separate organizations and their audit records
