## Why

Operators need to select device models for enrollment and sign-in testing before changing passkey writers.

## What Changes

Add a read-only PostgreSQL inventory recipe and explain how to interpret its counts.

## Capabilities

### Modified Capabilities

- `passkey-management` adds an operator inventory of enrolled credential groups.

## Impact

Adds a local operator command that reads the passkeys table.
