## Why

Large valid modules can fit in a validation request but receive HTTP 413.

## What Changes

Apply the existing request envelope limit and admit all source strings representable within it.

## Capabilities

### Modified Capabilities
- admin-hook-inventory

## Impact

Affects the validation handler and its isolated parser.
