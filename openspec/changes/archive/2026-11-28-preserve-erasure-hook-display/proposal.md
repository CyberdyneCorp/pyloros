## Why
Queued account deletion hooks print the erased subject before the event type. Operators comparing histories see a different context string for the same operation.

## What Changes
Give deletion components an explicitly ordered two-field context at delivery.

## Capabilities
### Modified Capabilities
- wasm-hook-components

## Impact
Affects new and pending deletion hook executions.
