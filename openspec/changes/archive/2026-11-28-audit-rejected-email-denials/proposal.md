## Why

A recipient's refusal matters to an operator even if PostgreSQL subsequently rejects the challenge update.

## What Changes

Retain the refusal in the authentication trail after explicit rollback.

## Capabilities

### Modified Capabilities
- `mfa-challenges` covers the audit of emailed sign-in denials.

## Impact

Changes the decision history visible to administrators.
