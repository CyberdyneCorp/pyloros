## Why

An administrator can revoke a session while an outstanding request rotates its refresh credential. The incoming writer needs the committed result of the outgoing operation.

## What Changes

Document and verify the session state required across a drained writer switch.

## Capabilities

### Modified Capabilities

- `grant-sessions` specifies revocation across a writer switch.

## Impact

Applies to cutover verification and operator documentation.
