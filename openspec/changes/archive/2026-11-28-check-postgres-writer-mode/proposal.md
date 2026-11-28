## Why
The reviewed hook inventory can match on a standby. Operators need to identify the server role and connection mode before reopening producers.

## What Changes
Add a just recipe that inspects the configured PostgreSQL connection without issuing a write.

## Capabilities
### Modified Capabilities
- `health` gains a local writer-mode check for cutover.

## Impact
Operator tooling and rollout documentation.
