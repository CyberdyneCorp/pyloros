## Why

A failure that escapes the application has a distinct HTTP contract. Clients comparing error responses need to distinguish it from a failure explicitly returned by a handler.

## What Changes

Apply browser, transport and cross-origin response policies only when the application handles the response.

## Capabilities

### Modified Capabilities

- `http-responses` defines which response policies apply to unhandled internal failures.

## Impact

Shared HTTP middleware and endpoints returning the generic internal error document.
