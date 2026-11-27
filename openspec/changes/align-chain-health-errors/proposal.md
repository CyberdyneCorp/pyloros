## Why

The administrator health read reports whether the configured provider is reachable. Operators need the underlying RPC failure to diagnose outages and confirm recovery.

## What Changes

Share provider transport and response handling between status checks and other chain reads. Preserve the health deadline and selected provider.

## Capabilities

### Modified Capabilities
- `iam-role-claims` clarifies diagnostics and retries on administrator chain health reads.

## Impact

Chain health, provider reads and their regression tests.
