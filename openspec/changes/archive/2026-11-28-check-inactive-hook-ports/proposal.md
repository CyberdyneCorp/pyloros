## Why

A disabled hook can be reactivated after cutover. Operators retiring the legacy runtime need to identify every stored definition that still requires a component.

## What Changes

Add an optional coverage check for active and inactive definitions to the existing inventory and reviewed-report workflow.

## Capabilities

### Modified Capabilities

- `admin-hook-inventory`

## Impact

Operator CLI, inventory report and just recipes.
