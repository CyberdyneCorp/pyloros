## ADDED Requirements

### Requirement: Add an organization membership

An operator SHALL be able to add an existing user to an active organization while preserving their primary organization. The service SHALL return HTTP 201 with a JSON null body on success and atomically record the operator action and membership.

#### Scenario: Repeat an addition

- **WHEN** the user already belongs to the selected organization
- **THEN** retain one membership and audit the accepted request

#### Scenario: Audit failure

- **WHEN** the operator action cannot be recorded
- **THEN** roll back the membership addition

#### Scenario: Overlapping first additions

- **WHEN** two requests have both observed that the membership is absent before either insert commits
- **THEN** commit one addition and its audit, return a server error for the conflicting insert, and allow a later retry to succeed
