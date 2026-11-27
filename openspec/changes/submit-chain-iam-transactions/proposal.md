## Why

Operator policy creation, replacement and deletion must also work when the configured IAM provider stores policies on chain.

## What Changes

Add a shared transaction sender for the configured IAM provider. Connect all three policy mutations and verify their HTTP responses and operator audit behavior.

## Capabilities

### New Capabilities
- `chain-iam-transactions` covers transaction submission and confirmation for IAM changes.

## Impact

IAM provider configuration, administrator write handlers, chain transport and audit records.
