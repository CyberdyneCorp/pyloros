## Why
A disputed role write can leave an audit entry and webhook delivery even when the provider rejected the transaction. Operators need to check the group's actual membership at a reproducible block.

## What Changes
Add a read-only just recipe for checking a single identity token in a specified chain group at a canonical block hash.

## Capabilities
### Modified Capabilities
- `iam-role-claims` covers membership reconciliation during writer handoff.

## Impact
Operator CLI and handoff documentation.
