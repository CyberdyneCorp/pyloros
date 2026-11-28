## ADDED Requirements

### Requirement: Coordinate role assignment preparations across replicas
Operator and delegated chain-backed role edits SHALL hold the shared PostgreSQL signer lock throughout unsigned membership transaction preparation. A grant that prepares creation of a missing organization role group SHALL use the same lock.

#### Scenario: Concurrent addition and removal
- **WHEN** separate replicas prepare a grant and revocation using the same signer
- **THEN** the second preparation waits to read the pending nonce until the first preparation ends

#### Scenario: Missing scoped group
- **WHEN** an eligible scoped grant needs a new group while a role transaction is in preparation for the same signer
- **THEN** wait for that preparation before reading the pending nonce for group creation
