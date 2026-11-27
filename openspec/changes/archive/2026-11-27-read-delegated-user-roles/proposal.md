## Why

A service client needs the current roles of a user when making authorization decisions.

## What Changes

Add a delegated user-role lookup.

## Capabilities

### Modified Capabilities
- `delegated-role-inventory`

## Impact

Reads existing IAM assignments and active organization memberships.
