## Why

Passkey clients can stream a request without declaring its size. The byte limit applies across chunks and every accepted byte must reach the handler.

## What Changes

Specify the request-size boundary across passkey operations and cover both fixed and streamed uploads.

## Capabilities

### Modified Capabilities
- passkey-management

## Impact

HTTP contract and middleware regression tests.
