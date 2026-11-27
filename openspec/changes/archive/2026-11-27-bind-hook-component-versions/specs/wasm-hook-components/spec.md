## ADDED Requirements

### Requirement: Select a staged version for a hook
The service SHALL allow a current administrator to read, set, replace or release the component version selected for a stored hook.
#### Scenario: Select a staged version
- **WHEN** an administrator selects an existing artifact for a hook
- **THEN** atomically save the binding and audit the old and new digests while preserving the hook's settings
#### Scenario: Retry a completed update
- **WHEN** the selected digest already matches the requested value or an already empty binding is released
- **THEN** return the current binding without an additional audit entry
#### Scenario: Reject an unknown version
- **WHEN** the requested digest has no staged artifact
- **THEN** return a missing-artifact error and preserve the prior binding
