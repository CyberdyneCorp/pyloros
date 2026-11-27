## Why
Operators need to register destinations and change their subscriptions from the existing administration clients.

## What Changes
Add administrative creation and partial editing to the subscription API.

## Capabilities
### Modified Capabilities
- webhook-history

## Impact
The administrative HTTP service writes subscription rows and audit history in PostgreSQL.
