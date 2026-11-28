## Why

Every point check needs both the application's current model and the account's eligibility. Reading these independently adds a database round trip.

## What Changes

Fetch both inputs in one statement within the permission snapshot.

## Capabilities

### Modified Capabilities

- `relationship-authorization` preserves existing responses while reducing database requests.

## Impact

Changes the PostgreSQL read path for direct and inherited checks.
