## Why

The shared login page and CLI need to initiate external sign-in through either backend during migration.

## What Changes

Accept sign-in requests for configured Google and Microsoft providers and preserve callback state in PostgreSQL.

## Capabilities

### New Capabilities

- `external-oauth` covers initiation and return routing.

## Impact

Uses the existing provider configuration, redirect allowlist and shared database. Callback processing remains on the existing service during this increment.
