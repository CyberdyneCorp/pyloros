## Why

A receiver can acknowledge a delivery using a raw DEFLATE response. Treating the response as unreadable schedules another delivery after acknowledgement.

## What Changes

Decode both common HTTP deflate formats before recording receiver status and a bounded excerpt.

## Capabilities

### Modified Capabilities
- webhook-delivery

## Impact

Outbound webhook attempts and their persisted results.
