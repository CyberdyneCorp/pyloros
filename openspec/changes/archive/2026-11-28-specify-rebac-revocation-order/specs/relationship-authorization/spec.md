## ADDED Requirements

### Requirement: Retire an assigned relation across replicas
When replacing a model would invalidate an existing assignment, the service SHALL evaluate the assignment against the committed state when the writer acquires the client lock. Revoking the last blocking assignment SHALL allow a subsequent replacement to succeed.

#### Scenario: Revocation commits first
- **GIVEN** one assignment blocks the proposed removal and provides the user's only path to a permission
- **WHEN** the revocation commits before the replacement
- **THEN** both writes return HTTP 204, both changes are audited, and subsequent checks on either replica deny that permission

#### Scenario: Replacement attempts to commit first
- **WHEN** the replacement encounters the last blocking assignment before its revocation commits
- **THEN** the replacement returns HTTP 409 and the old model stays installed
- **AND** the revocation succeeds under the old model and a new replacement request can install the proposed model

#### Scenario: Retry after both changes commit
- **WHEN** the caller repeats the revocation and model replacement after both changes have committed
- **THEN** both requests return HTTP 204 and neither appends another change audit
