## Why

Operators need to create IAM groups through the existing CLI and console before assigning policies or members.

## What Changes

Add group creation through the selected IAM provider and preserve the separate namespace for client roles.

## Capabilities

### Modified Capabilities
- `operator-iam-inventory` gains group creation.

## Impact

Operator HTTP handlers, group persistence and auditing.
