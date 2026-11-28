## Why

Operators need to manage a graph and check individual access decisions using their usual service credentials.

## What Changes

Expose typed model, grant, revoke and check commands in the operator CLI and associate each command with its published OpenAPI operation.

## Impact

The Rust command module is distributed here. The existing operator CLI supplies the transport and credential handling.
