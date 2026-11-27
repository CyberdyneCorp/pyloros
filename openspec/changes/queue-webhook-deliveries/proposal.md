## Why

Operators need to check a destination and retry a finished delivery while retaining its original event for receiver-side deduplication.

## What Changes

Add administrative endpoints to queue a test for one subscription and restart a terminal delivery.

## Capabilities

### Modified Capabilities
- `webhook-history` gains operator actions on the delivery queue.

## Impact

Use the existing PostgreSQL outbox, attempt history and administrative audit log.
