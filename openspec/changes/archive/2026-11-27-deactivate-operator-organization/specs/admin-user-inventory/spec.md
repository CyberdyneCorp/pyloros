## ADDED Requirements

### Requirement: Deactivate an organization

An operator SHALL be able to deactivate an organization while preserving membership references and recording the action atomically.

#### Scenario: Retire an active organization

- **WHEN** an operator deletes an existing organization
- **THEN** return an empty 204 response with the JSON content type and exclude the organization from active membership results

#### Scenario: Retry a deactivation

- **WHEN** an operator repeats the request for an inactive organization with unchanged directory data
- **THEN** record the accepted action and return 204 while preserving the directory update timestamp

#### Scenario: Audit failure

- **WHEN** the action cannot be recorded
- **THEN** roll back the directory update
