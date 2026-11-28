## Why

Clients with many organization-specific role groups incur unnecessary membership counts during global role inventory.

## What Changes

Exclude organization-qualified group names from PostgreSQL global inventory and role capacity reads.

## Capabilities

### Modified Capabilities

- `admin-oauth-client-management` covers recovery of an existing oversized global role catalog and the scope of its member counts.

## Impact

Applies to operator and delegated role catalog endpoints backed by PostgreSQL.
