## Why

The existing operator clients need a searchable directory and account details during the backend migration.

## What Changes

Implement administrative user collection and detail reads.

## Capabilities

### New Capabilities

- `admin-user-inventory` — Inspect account metadata, identities and activity.

## Impact

Reads use the existing operator access checks and shared PostgreSQL data.
