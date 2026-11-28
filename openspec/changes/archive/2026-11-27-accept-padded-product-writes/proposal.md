## Why
The encoded length of a JSON product edit can exceed two MiB even when every submitted field fits its domain limit.

## What Changes
Allow these documents through the four product write handlers. Keep existing field validation and administrator checks.

## Capabilities
### New Capabilities
None.

### Modified Capabilities
- `store-product-mappings` defines envelope handling for catalog and storefront writes.

## Impact
The affected requests are virtual product creation and patching and Apple and Google mapping creation.
