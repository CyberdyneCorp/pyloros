## ADDED Requirements

### Requirement: Evaluate model replacements at the commit boundary
A permission check SHALL use a single committed model and graph snapshot. After a model replacement returns HTTP 204, a new check on any API replica sharing the PostgreSQL primary SHALL evaluate the committed model.

#### Scenario: Remove an inherited permission rule
- **WHEN** a pending replacement retains direct membership and removes the parent traversal rule
- **THEN** a check taking its snapshot before commit sees the prior committed rule
- **AND** after commit a new check denies access derived solely from that parent while allowing direct membership

#### Scenario: Model audit rolls back
- **WHEN** recording a changed model fails and the transaction rolls back
- **THEN** subsequent checks continue to use the previously committed model and assignments
