## Why

Waiting for an account lock can move a password session past a concurrent sign-out cutoff.

## What Changes

Carry the successful password verification time through single-step session issuance.

## Capabilities

### Modified Capabilities
- account-passwords
- grant-sessions

## Impact

Password-only sign-in and initial session persistence for password and OAuth grants.
