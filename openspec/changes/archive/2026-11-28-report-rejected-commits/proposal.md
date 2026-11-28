## Why

A successful response can cause a client to rely on a session, credential or queued operation that the database discarded.

## What Changes

Document HTTP 500 as the intentional migration response to an explicit rejection at commit.

## Capabilities

### Modified Capabilities
- `http-responses` governs responses for transactions rejected at commit.

## Impact

Applies to handlers that require a successful commit before releasing their response.
