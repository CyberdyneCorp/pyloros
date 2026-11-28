## Why
A refresh can renumber previously duplicated rules. Operators need to detect repeated stored content even when every position is unique.

## What Changes
Add an optional content comparison to the read-only IAM statement inventory.

## Capabilities
### Modified Capabilities
- operator-iam-inventory

## Impact
The optional mode reads the rule columns and emits aggregate counts.
