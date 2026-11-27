## Why

Operators need to retire an IAM group and revoke access inherited through it.

## What Changes

Support deleting an ordinary group, preserve client-role namespace ownership, and audit confirmed changes.

## Capabilities

### Modified Capabilities
- `operator-iam-inventory` gains group deletion.

## Impact

Operator IAM HTTP handlers, group relationships, chain transport and audit records.
