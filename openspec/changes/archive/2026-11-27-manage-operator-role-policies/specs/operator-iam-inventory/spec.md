## ADDED Requirements

### Requirement: Manage role policies

An authorized operator SHALL be able to attach a policy to a role and detach it through the selected IAM provider.

#### Scenario: Change permissions for an existing session

- **WHEN** an operator attaches or removes the only role policy granting access to an identity with an active role session
- **THEN** the next access evaluation reflects the change

#### Scenario: Retry a database relationship edit

- **WHEN** an operator repeats a successful edit
- **THEN** the relationship has the requested state and each successful request has its own audit entry

#### Scenario: Failed database audit

- **WHEN** recording the operator action fails
- **THEN** the prior relationship state is preserved
