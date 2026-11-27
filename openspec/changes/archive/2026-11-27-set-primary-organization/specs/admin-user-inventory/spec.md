## ADDED Requirements

### Requirement: Manage primary organization

An operator SHALL be able to set or clear the primary organization of an existing user. The operator audit, primary organization and explicit membership changes SHALL commit together.

#### Scenario: Assign active organization

- **WHEN** the operator assigns an active organization
- **THEN** record it as primary, ensure the user has an explicit membership and return an empty 204 response

#### Scenario: Clear primary organization

- **WHEN** the operator submits an assignment document with an omitted or null organization identifier
- **THEN** clear the primary organization and retain existing explicit memberships

#### Scenario: Assignment rejected

- **WHEN** the requested organization is missing or inactive
- **THEN** return a missing-resource response and preserve the user's previous assignment
