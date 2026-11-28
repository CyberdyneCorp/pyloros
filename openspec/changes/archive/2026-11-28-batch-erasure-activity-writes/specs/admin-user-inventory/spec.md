## ADDED Requirements

### Requirement: Bounded persistence of rewritten authentication events

The service SHALL persist retained authentication events in bounded batches within the account erasure transaction. Each retained event SHALL keep its identifier and receive the canonical hash of its own rewritten content.

#### Scenario: A later batch fails
- **WHEN** a database write fails after an earlier batch has been updated during erasure
- **THEN** the account, session state and earlier event contents and hashes are restored by rollback

#### Scenario: Several batches commit
- **WHEN** erasure commits a history spanning multiple batches
- **THEN** the receipt counts every rewritten event exactly once
