## Why

Operators need to grant or revoke access for every member of a group through a shared policy.

## What Changes

Add operator controls for attaching and detaching an existing IAM policy through the selected provider.

## Capabilities

### Modified Capabilities

- `operator-iam-inventory` gains group policy attachment and detachment.

## Impact

Operator HTTP routes, inherited authorization, provider reads and writes, and operator audit records.
