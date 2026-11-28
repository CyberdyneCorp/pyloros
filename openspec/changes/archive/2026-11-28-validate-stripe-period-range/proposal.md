## Why
An out-of-range subscription period can be mistaken for a missing expiry or stored beyond the date range supported by billing readers.

## What Changes
Validate the selected period before recording a signed Stripe event. Allow a corrected delivery to use the same event identifier after failure.

## Capabilities
- Modified capability: stripe-billing-events
