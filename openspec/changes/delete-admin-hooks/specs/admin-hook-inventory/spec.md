## ADDED Requirements

### Requirement: Remove a stored hook
The service SHALL allow a current administrator to delete an installed hook and record that action.

#### Scenario: Delete a hook with history
- **WHEN** an administrator deletes a hook
- **THEN** remove its definition and associated executions and acknowledge the committed operation with HTTP 204

#### Scenario: Repeated removal
- **WHEN** an administrator deletes a hook that has already been removed
- **THEN** return HTTP 404 and preserve the existing deletion audit history
