## ADDED Requirements

### Requirement: Recover a product write after confirmed rollback
A rejected transaction SHALL preserve the previously committed product and audit state. After the cause of rejection has cleared, a successful retry of the same mutation through another writer on the same database SHALL apply the requested change and commit one audit entry when there have been no intervening writes.

#### Scenario: Retry product creation
- **WHEN** the database rolls back creation of a product with a new key
- **THEN** the catalog omits that key and its creation audit is absent
- **AND** a successful retry creates one active product and one creation audit

#### Scenario: Retry an edit or deactivation
- **WHEN** the database rolls back a product patch or deactivation
- **THEN** both writers can still read the previous fields and active flag
- **AND** a successful retry applies the edit or deactivation and adds its audit entry exactly once
