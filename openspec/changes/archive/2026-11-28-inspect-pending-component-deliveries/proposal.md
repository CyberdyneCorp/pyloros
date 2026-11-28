## Why
A writer handoff can require earlier component hooks to finish before the next writer accepts work. Binding coverage alone cannot tell the operator whether deliveries are still queued.

## What Changes
Add a read-only CLI and just recipe to count pending deliveries for all or selected event types.

## Capabilities
### Modified Capabilities
- `wasm-hook-components` gains a queue check for operator handoff.

## Impact
Operator CLI, runbook and PostgreSQL queue inspection.
