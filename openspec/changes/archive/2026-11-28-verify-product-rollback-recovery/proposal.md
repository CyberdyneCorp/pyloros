## Why

During a catalog writer handoff, operators need to establish whether a failed transaction changed a product before retrying it.

## What Changes

Specify the visible product state and audit history after a rejected commit and a subsequent successful retry.

## Capabilities

### Modified Capabilities

- store-product-mappings

## Impact

Product creation, patching and deactivation on a shared PostgreSQL catalog.
