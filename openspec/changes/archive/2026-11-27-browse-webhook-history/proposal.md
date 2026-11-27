## Why

Administrators need to inspect configured webhook destinations and diagnose failed deliveries.

## What Changes

Expose subscription inventory, subscription details and paginated delivery history through the administrative API.

## Capabilities

### New Capabilities
- `webhook-history` covers administrative reads of subscriptions and delivery attempts.

## Impact

Use the existing PostgreSQL webhook tables. Reading these reports does not enqueue deliveries.
