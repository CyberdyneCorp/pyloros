## Why
Concurrent edits can leave ordinary PostgreSQL policies with multiple statements at one position. The existing position and rule-content reports cover chain-linked policies only.

## What Changes
Add an optional all-policy scope to both aggregate reports.

## Capabilities
### Modified Capabilities
- operator-iam-inventory

## Impact
Extends the existing read-only operator command for shared-database migration checks.
