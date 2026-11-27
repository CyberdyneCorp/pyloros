## Why

Operators need a searchable history of privileged changes during migration.

## What Changes

Expose the audit directory with pagination and filters for actions, actors and targets.

## Capabilities

### New Capabilities
- `admin-audit` provides administrative access to the operator audit history.

## Impact

Reads the existing PostgreSQL audit table through the first-party administrator authorization check.
