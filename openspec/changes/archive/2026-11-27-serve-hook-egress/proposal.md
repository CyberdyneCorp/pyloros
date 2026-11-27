## Why

Operators need to distinguish availability of controlled network access for hooks from database readiness.

## What Changes

Run an HTTP CONNECT listener with destination checks and expose its availability on the readiness endpoint.

## Capabilities

### Modified Capabilities
- `health` reports hook egress availability when hooks are enabled.

## Impact

The hook egress listener has its own bind address and a default-deny domain policy.
