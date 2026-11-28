## Why
Billing producers depend on coverage for both grant and revoke hooks. Separate inventory runs can observe different binding states.

## What Changes
Accept multiple event names in the binding inventory command. Report their combined coverage in one read-only snapshot.

## Capabilities
### Modified Capabilities
- `admin-hook-inventory` gains a multi-event filter.

## Impact
Operator CLI, PostgreSQL inventory query and cutover guidance.
