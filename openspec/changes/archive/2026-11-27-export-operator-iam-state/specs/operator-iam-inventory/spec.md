## ADDED Requirements

### Requirement: Export operator IAM state

An authorized operator SHALL be able to export PostgreSQL IAM state as a versioned JSON document containing policies, groups, roles, identities, permission boundaries and their references.

#### Scenario: Export with chain IAM configured

- **WHEN** an operator exports IAM state while the chain provider is configured
- **THEN** return the stored database entities including their available chain references and the export time

#### Scenario: Audit the disclosure

- **WHEN** an export succeeds
- **THEN** record the operator and inventory counts in the audit without copying identity attributes into the audit metadata

#### Scenario: Audit unavailable

- **WHEN** the export audit cannot be committed
- **THEN** return an error without releasing the export document
