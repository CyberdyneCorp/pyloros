## Why
During IAM import handoff, operators need to know whether multiple stored rules occupy the same position in a chain-linked policy.

## What Changes
Add a database inventory reporting the number of affected policies, repeated positions and excess rows.

## Capabilities
### Modified Capabilities
- operator-iam-inventory

## Impact
The operator toolbox gains a read-only PostgreSQL command.
