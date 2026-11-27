## Why

Operators use the policy editor and CLI to create and revise the access rules shown in the IAM inventory.

## What Changes

Implement policy creation and replacement for the configured IAM provider.

## Capabilities

### Modified Capabilities

- `operator-iam-inventory` gains audited creation and update operations.

## Impact

The selected provider persists policy metadata and ordered statements. The operator API records the action and returns the provider's policy representation.
