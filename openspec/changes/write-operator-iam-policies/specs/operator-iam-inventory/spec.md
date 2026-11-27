## ADDED Requirements

### Requirement: Create an IAM policy

An authenticated operator SHALL be able to create a policy with a name, optional description and ordered statements. The service SHALL return the new policy and audit its identifier.

#### Scenario: PostgreSQL creation

- **WHEN** an operator creates a valid policy on the PostgreSQL provider
- **THEN** return the policy with its initial version and make it available through the individual policy read

### Requirement: Update an IAM policy

An authenticated operator SHALL be able to replace a policy's statements and update supplied metadata through the configured provider.

#### Scenario: Replace statements on PostgreSQL

- **WHEN** an operator submits an update to an existing PostgreSQL policy
- **THEN** replace its statements, advance its version, retain its identifier and record the operator action

#### Scenario: Audit write fails on PostgreSQL

- **WHEN** the required audit record cannot be saved
- **THEN** roll back the policy and statement changes
