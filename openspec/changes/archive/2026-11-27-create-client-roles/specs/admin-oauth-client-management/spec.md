## ADDED Requirements

### Requirement: Create a PostgreSQL client role

An authenticated operator SHALL be able to create a global role in an active client catalog with an optional description. The service SHALL enforce the 64-role limit per client, reject duplicate keys, clear any previous permission mapping for a newly created role and audit successful creation atomically.

#### Scenario: Reuse an available key

- **WHEN** an operator creates an available role key for an active client using PostgreSQL IAM
- **THEN** the API returns the new role with zero members, and its permission mapping is empty

#### Scenario: Audit write fails

- **WHEN** the audit record cannot be persisted
- **THEN** the role creation and mapping cleanup roll back together
