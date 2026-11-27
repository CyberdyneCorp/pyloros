## Why

Operators need to inspect a single policy before editing it in the existing IAM console.

## What Changes

Serve an individual policy by its provider-specific UUID.

## Capabilities

### Modified Capabilities

- `operator-iam-inventory` adds individual policy retrieval.

## Impact

Provide the read operation used by the existing CLI and the policy editor.
