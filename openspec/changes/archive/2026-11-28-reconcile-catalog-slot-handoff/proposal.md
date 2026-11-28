## Why

Operator and delegated requests share each client's catalog capacity. Switching writers while the final creation is still in flight can leave the incoming writer with a stale count.

## What Changes

Document and verify admission, committed inventory readback and incoming creation for both catalogs.

## Capabilities

### Modified Capabilities

- `admin-oauth-client-management` covers catalog capacity after a writer switch.

## Impact

Covers PostgreSQL deployments performing a controlled handoff.
