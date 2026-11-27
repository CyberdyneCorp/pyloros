## Why

During migration, the Rust service needs to accept email verification credentials already delivered to account owners.

## What Changes

Implement the public email verification endpoint and reuse the domain membership rules used during password recovery.

## Capabilities

### Modified Capabilities

- `user-profile` supports proving account email ownership.

## Impact

The operation updates the existing account, email verification credential, membership and audit tables.
