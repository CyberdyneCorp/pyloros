## Why

Checking a permission through many teams currently issues a separate membership query per team even when all teams use the same direct rule.

## What Changes

Group same-type, same-permission objects that have a single direct rule into one bounded membership read.

## Capabilities

### Modified Capabilities

- `relationship-authorization` covers grouped direct membership evaluation.

## Impact

Affects the Rust relationship evaluator and its PostgreSQL coverage.
