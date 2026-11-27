## Why

Operators need to retire unused policies from the existing console and CLI.

## What Changes

Implement individual policy deletion and report whether the policy is missing or still attached.

## Capabilities

### Modified Capabilities
- `operator-iam-inventory` gains a policy deletion operation.

## Impact

Operator IAM HTTP handlers, provider access and auditing.
