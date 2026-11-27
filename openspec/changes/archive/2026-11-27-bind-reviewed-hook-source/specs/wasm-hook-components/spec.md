## ADDED Requirements

### Requirement: Select a component for reviewed source
An administrator SHALL be able to condition component selection on the SHA-256 of the stored hook source encoded as UTF-8. The check and selection SHALL be atomic with respect to edits of that definition.

#### Scenario: Reviewed source is current
- **WHEN** the caller supplies the current source digest and an installed artifact digest
- **THEN** select the requested artifact and include the reviewed source digest in the audit entry when the selection changes

#### Scenario: Source has changed
- **WHEN** the supplied source digest differs from the current source
- **THEN** return HTTP 409, preserve the binding and its audit history, including when the requested artifact is already selected

#### Scenario: Caller omits the source digest
- **WHEN** a caller submits only an artifact digest
- **THEN** apply the existing selection behavior
