## Why

Operators need to assign and clear the organization used to resolve a user's primary organization entitlements.

## What Changes

Implement the primary organization assignment endpoint on the Rust backend.

## Capabilities

### Modified Capabilities

- `admin-user-inventory` gains primary organization assignment.

## Impact

Update PostgreSQL user, membership and operator audit records in one transaction.
