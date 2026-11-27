## Why

Operators need to inspect the permission keys an application has registered before assigning them to roles.

## What Changes

Expose an authenticated, read-only permission inventory for a named client.

## Capabilities

### Modified Capabilities
- `admin-oauth-client-reads` expands to include the client's permission catalog.

## Impact

Uses the existing administrator session and PostgreSQL registry.
