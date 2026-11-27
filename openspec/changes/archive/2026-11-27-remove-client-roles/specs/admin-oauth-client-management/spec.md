## ADDED Requirements

### Requirement: Remove a PostgreSQL client role

An operator SHALL be able to remove a role and its organization assignments from an active client. The service SHALL remove its permission mapping and record the deletion atomically.

#### Scenario: Only an organization assignment remains

- **WHEN** the requested role has an organization group and no global group
- **THEN** deletion succeeds and removes that assignment

#### Scenario: The role does not exist

- **WHEN** no matching global or organization group exists
- **THEN** the operation returns a missing-role error and preserves any existing mapping
