## Why

Service clients need to assign catalog permissions to their own roles.

## What Changes

Add the delegated permission replacement operation and service actor audit attribution.

## Capabilities

### Modified Capabilities
- `delegated-role-inventory`

## Impact

Uses the active IAM role provider and PostgreSQL permission mappings.
