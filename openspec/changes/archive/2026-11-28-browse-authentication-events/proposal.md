## Why

Operators investigating a sign-in need its outcome and supporting context. Reviewing this history is itself an auditable action.

## What Changes

Add global and per-user authentication history, search filters and cursor pagination.

## Capabilities

### Modified Capabilities
- `admin-audit` gains authentication-event history.

## Impact

Reads PostgreSQL authentication events and appends administrative audit records.
