## Why

An operator needs to try an installed hook with sample data from the existing console or CLI before enabling it.

## What Changes

Expose manual execution through the v1 operator API. Execute the WebAssembly component selected for the requested hook and record the operator action.

## Capabilities

### Modified Capabilities

- admin-hook-inventory

## Impact

Uses the existing component worker, operator audit and binding tables.
