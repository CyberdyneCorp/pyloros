## Why

The source validator accepts yield expressions that fail compilation in a comprehension.

## What Changes

Respect comprehension scope when checking yields in submitted modules.

## Capabilities

### Modified Capabilities

- admin-hook-inventory

## Impact

Stored hook source validation in the isolated worker.
