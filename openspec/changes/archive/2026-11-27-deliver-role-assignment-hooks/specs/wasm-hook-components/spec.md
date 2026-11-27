## ADDED Requirements

### Requirement: Deliver PostgreSQL role changes
The service SHALL deliver a version-pinned event for each accepted PostgreSQL role assignment or withdrawal when role hook dispatch is enabled.

#### Scenario: Administrator or delegated change
- **WHEN** an authorized writer grants or revokes a role
- **THEN** deliver the event type, target user, resolved client and role key, and include the organization id for a scoped assignment

#### Scenario: Repeat assignment or withdrawal
- **WHEN** the membership already has the requested state and the write succeeds
- **THEN** queue an event for that accepted write

#### Scenario: Remove organization membership
- **WHEN** removing a user from an organization withdraws scoped roles
- **THEN** queue a revocation for each withdrawn assignment in the same transaction

#### Scenario: Roll back the role write
- **WHEN** the enclosing operation fails to commit
- **THEN** expose neither a queued delivery nor an execution record for that operation
