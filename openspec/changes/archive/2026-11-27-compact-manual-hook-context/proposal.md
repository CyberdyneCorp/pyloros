## Why
Formatting inside a v1 manual context can make a small event exceed the component input budget.

## What Changes
Remove insignificant JSON whitespace when the submitted context exceeds the worker limit. Retain the existing error and audit behavior for oversized event data.

## Capabilities
### Modified Capabilities
- admin-hook-inventory

## Impact
Manual component tests on the v1 operator route.
