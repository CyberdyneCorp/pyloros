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

#### Scenario: Repair historical statement data

- **WHEN** an administrator replaces stored rules containing non-string action or resource entries, or structured condition keys or values, with valid new statements
- **THEN** accept the replacement if the stored rule collections, effects and condition operators can be decoded
- **AND** if the transaction is explicitly rejected at commit, return HTTP 500 and preserve the original statement rows, policy version and audit history

#### Scenario: Stored rule structure is invalid

- **WHEN** an old rule contains a non-iterable action collection, an unknown condition operator, or a condition missing a required key
- **THEN** fail the replacement without changing the policy or recording a successful edit
