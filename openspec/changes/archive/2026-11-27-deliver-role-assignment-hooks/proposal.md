## Why
Applications receiving PostgreSQL role changes need to run their selected hook version after a membership transaction commits.
## What Changes
Queue component deliveries for administrator and delegated role edits, including scoped withdrawals during organization membership removal.
## Capabilities
### Modified Capabilities
- `wasm-hook-components` delivers PostgreSQL role assignments and withdrawals.
## Impact
Uses the existing queue and worker with an independent role delivery switch.
