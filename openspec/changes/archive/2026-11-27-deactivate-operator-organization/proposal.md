## Why

Operators need to retire an organization while keeping its historical membership records.

## What Changes

Support soft deactivation through the operator organization endpoint.

## Capabilities

### Modified Capabilities

- `admin-user-inventory` adds organization deactivation.

## Impact

The Rust service updates the PostgreSQL directory and operator audit in a single transaction.
