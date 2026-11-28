## Why

An operator transferring a pending delivery needs to know which schedule the incoming worker will follow after a receiver reports throttling.

## What Changes

Specify the persisted retry deadline for HTTP 429 and its effect on worker handoff.

## Capabilities

### Modified Capabilities

- webhook-delivery

## Impact

Outbound delivery scheduling and receiver integration documentation.
