## ADDED Requirements

### Requirement: Recover an existing oversized permission catalog
The operator and delegated permission endpoints SHALL expose every stored permission in the authorized client's catalog and allow explicit deletion when the catalog exceeds 256 entries.

#### Scenario: Attempt a creation while full
- **WHEN** the catalog already holds at least 256 keys
- **THEN** return HTTP 409 for creation, identifying an existing key as a duplicate and a new key as exceeding capacity

#### Scenario: Recreate a retired permission
- **WHEN** deletion reduces the catalog below 256 and a caller creates a previously retired key
- **THEN** create the permission and leave its former role assignments removed
