## Why
Printing a queued role event exposes PostgreSQL's JSONB key ordering in execution history. Administrators comparing hook output across a migration see different strings for the same role assignment.

## What Changes
Restore the role event field sequence when the worker claims a delivery.

## Capabilities
### Modified Capabilities
- wasm-hook-components

## Impact
Affects queued role grant and revoke events, including existing deliveries.
