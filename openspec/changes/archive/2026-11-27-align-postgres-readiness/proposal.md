## Why
Operators use readiness to distinguish schema upgrades, exhausted connections and database outages during migration.

## What Changes
Report observed database failure classes and honor database lock handling during migration checks. Align simultaneous readiness checks with the reference connection ceiling and wait window.

## Capabilities
### Modified Capabilities
- health

## Impact
Database pool sizing, readiness responses and tests.
