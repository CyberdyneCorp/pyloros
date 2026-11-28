## Why

An existing client can have more permissions than a new catalog permits. Operators need predictable reads, removals and new-key responses during migration.

## What Changes

Define how both catalog writers behave above the limit and when capacity becomes available again.

## Capabilities

### Modified Capabilities

- `delegated-permission-catalog` describes shared catalog recovery.

## Impact

Covers PostgreSQL catalog reads, creates, deletions and role permission mappings.
