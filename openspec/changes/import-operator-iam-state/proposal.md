## Why

Operators need to reconcile the configured chain's IAM catalog with PostgreSQL.

## What Changes

Add an operator-triggered import of the deployed provider's readable IAM state.

## Capabilities

### Modified Capabilities
- `operator-iam-inventory` gains chain snapshot import.

## Impact

Operator API, chain reads, stored policies and groups, and audit history.
