## ADDED Requirements

### Requirement: Inspect related hook events together
The binding inventory SHALL accept multiple supported event names and report all matching definitions in hook ID order from one read-only PostgreSQL snapshot. Its exit code SHALL reflect active unbound definitions among the selected events.

#### Scenario: Check both entitlement transitions
- **WHEN** the operator selects grant and revoke events and an active revoke hook lacks a binding
- **THEN** report incomplete coverage even when all active grant hooks are bound
- **AND** omit unrelated events and include each matching definition once even if an event argument repeats

#### Scenario: Unknown name in a combined check
- **WHEN** any supplied name is unknown
- **THEN** return a usage error without emitting a partial inventory
