## Why

Operators must be able to inspect the permissions granted by a role before changing it.

## What Changes

Add the read operation for a single role’s permission mapping.

## Capabilities

### Modified Capabilities
- `admin-oauth-client-reads` includes the permission keys granted by a named role.

## Impact

The operator console and CLI can inspect the current mapping using the existing administrative session.
