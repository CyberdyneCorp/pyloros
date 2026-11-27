## Why

Operators investigating an account need its credential inventory even when passkey sign-in is disabled.

## What Changes

Add a read-only administrative user passkey collection.

## Capabilities

### Modified Capabilities

- `admin-user-inventory` gains a per-user credential list.

## Impact

The existing admin user detail screen can render passkey metadata from PostgreSQL.
