## Why

Operators need to know whether disabling a service client preserves its relationship graph and what a replacement registration inherits.

## What Changes

Document the observed permission-check responses across registration deactivation, reactivation and removal.

## Capabilities

### Modified Capabilities

- `relationship-authorization` defines how registration lifecycle affects stored relationships and checks.

## Impact

Clarifies the PostgreSQL contract and operator documentation.
