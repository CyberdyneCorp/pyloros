## Why
An unused request body can prevent an administrator from deactivating a product.

## What Changes
Dispatch deactivation and unsupported methods at the individual product URL using the method and path before reading body bytes.

## Capabilities
### Modified Capabilities
- `store-product-mappings` specifies body-independent deactivation.

## Impact
Only the individual virtual product route changes.
