## Why

Administrative OAuth routes attach Allow to ordinary GET responses, and the client collection advertises a different method on a method error. Clients receive a misleading account of the supported operations.

## What Changes

Match the established Allow header on administrative OAuth collection and detail routes.

## Capabilities

### Modified Capabilities

- `http-responses` — Method advertisement on the administrative OAuth API.

## Impact

Only method advertisement changes. Request handlers retain their authorization and validation order.
