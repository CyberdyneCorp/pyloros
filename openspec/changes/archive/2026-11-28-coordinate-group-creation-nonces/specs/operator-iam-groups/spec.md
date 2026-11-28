## ADDED Requirements

### Requirement: Coordinate unsigned group creation with operator policy writes
While preparing a chain-backed operator group creation, the service SHALL acquire the same PostgreSQL signer lock as operator policy mutations before reading the pending nonce and hold it until preparation finishes.

#### Scenario: Concurrent preparation on a second replica
- **WHEN** one replica is preparing a group creation and another attempts a policy creation with the same signer, or the requests arrive in reverse order
- **THEN** the second preparation waits before reading the pending nonce and may proceed once the first releases the lock

#### Scenario: Preparation reaches the submission boundary
- **WHEN** unsigned preparation completes and submission is unavailable
- **THEN** return HTTP 503 and leave the local group catalog and success audit unchanged
