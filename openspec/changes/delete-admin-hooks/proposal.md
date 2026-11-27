## Why
Operators need to remove retired hooks and the execution history linked to them.
## What Changes
Add the administrative delete operation for stored hooks.
## Capabilities
### Modified Capabilities
- admin-hook-inventory
## Impact
Removes hook records and linked runs from PostgreSQL and records the operator action.
