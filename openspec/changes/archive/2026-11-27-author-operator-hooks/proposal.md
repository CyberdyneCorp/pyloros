## Why

The operator console can read definitions and check source. Operators also need to save definitions and change their settings during migration.

## What Changes

Add creation and partial editing to the v1 hook inventory. Reuse the isolated validator and the transaction that records operator activity.

## Capabilities

### Modified Capabilities

- admin-hook-inventory

## Impact

Affects the PostgreSQL hook inventory, audit history and v1 operator API.
