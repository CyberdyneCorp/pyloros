## Why

Operators need to issue product access directly and restore access to an existing subscription.

## What Changes

Add the administrative grant operation for personal and organization subscriptions.

## Capabilities

### Modified Capabilities
- `admin-entitlements` gains manual grants.

## Impact

The grant and operator audit share a PostgreSQL transaction.
