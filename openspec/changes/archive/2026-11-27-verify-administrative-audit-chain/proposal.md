## Why

Operators need to check the integrity of retained privileged operation records after migration.

## What Changes

Add first-party administrative verification of the stored audit chain.

## Capabilities

### Modified Capabilities
- `admin-audit` gains an integrity report.

## Impact

The operation reads audit history from PostgreSQL and shares the record format used by the audit writer.
