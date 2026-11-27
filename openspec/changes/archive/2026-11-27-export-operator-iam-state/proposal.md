## Why

Operators need a portable view of stored IAM state for inspection and migration.

## What Changes

Add an authenticated IAM export that includes stored entities and the relationships between them.

## Capabilities

### Modified Capabilities
- `operator-iam-inventory` gains a versioned export document.

## Impact

Operator API, existing export clients and operator auditing.
