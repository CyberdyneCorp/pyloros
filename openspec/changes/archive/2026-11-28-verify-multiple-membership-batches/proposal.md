## Why

A permission can be granted by several teams that fall into different traversal batches. Revoking one path must preserve access through the others.

## What Changes

Specify and verify independent membership paths across multiple batches, including the final partial batch.

## Capabilities

### Modified Capabilities

- `relationship-authorization` covers revocation across team batches.

## Impact

Adds PostgreSQL regression coverage and deployment rehearsal results.
