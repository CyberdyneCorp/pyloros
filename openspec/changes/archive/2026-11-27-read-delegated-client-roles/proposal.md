## Why

Service clients need to discover their roles and inspect the permissions assigned to each role.

## What Changes

Serve delegated role inventory and role-permission reads.

## Capabilities

### New Capabilities
- `delegated-role-inventory`

## Impact

Uses the registered client, IAM provider and PostgreSQL permission mappings.
