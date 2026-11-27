## Why
Applications need a hosted payment session linked to the signed-in user and the product they selected.

## What Changes
Expose authenticated Stripe Checkout session creation.

## Capabilities
### New Capabilities
- stripe-checkout

## Impact
The endpoint reads the product catalog and customer mappings in PostgreSQL and calls the configured payment provider.
