## Why
A queued notification needs to reach its subscriber and expose its attempt history to operators.

## What Changes
Run a bounded outbound delivery worker alongside the HTTP service.

## Capabilities
### Modified Capabilities
- webhook-history

## Impact
The worker reads and updates the shared PostgreSQL outbox and makes signed HTTP requests.
