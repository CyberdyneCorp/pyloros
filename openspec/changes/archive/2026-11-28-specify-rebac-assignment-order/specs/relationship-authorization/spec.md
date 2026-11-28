## ADDED Requirements

### Requirement: Resolve conflicting model and assignment writes
Concurrent writes for one client SHALL leave every committed assignment valid under the committed model. Both replicas SHALL report the resulting permission decision on subsequent checks.

#### Scenario: Grant commits before model replacement
- **WHEN** a relationship grant commits before a competing model replacement that would invalidate it
- **THEN** return 204 for the grant and 409 for the replacement
- **AND** retain the assignment and its original model

#### Scenario: Model replacement commits before grant
- **WHEN** a model replacement removes a relation before a competing grant for that relation commits
- **THEN** return 204 for the replacement and 422 for the grant
- **AND** preserve the replacement model and omit the rejected assignment

#### Scenario: Retry both requests after the conflict
- **WHEN** the caller retries the same pair against the resulting state without intervening writes
- **THEN** return the same outcomes and create no additional change audit entries
