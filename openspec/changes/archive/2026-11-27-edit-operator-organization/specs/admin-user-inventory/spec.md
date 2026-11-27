## ADDED Requirements

### Requirement: Edit an organization

An operator SHALL be able to update an organization's directory fields, metadata and active status. The response SHALL include the resulting directory record and the service SHALL audit the accepted fields.

#### Scenario: Metadata edit

- **WHEN** an operator submits metadata entries
- **THEN** replace the submitted values, remove keys given an empty value, and retain other entries from the observed map

#### Scenario: Reactivation conflict

- **WHEN** reactivating an organization would assign a GitHub owner already mapped to an active organization
- **THEN** return a conflict and preserve its stored inactive status

#### Scenario: Audit failure

- **WHEN** the operator audit cannot be recorded
- **THEN** roll back the directory edit
