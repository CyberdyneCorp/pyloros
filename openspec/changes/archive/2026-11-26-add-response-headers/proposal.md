## Why

Clients should receive consistent browser protections on the initial read-only routes, including error responses.

## What Changes

Apply common headers after routing and select strict transport security from deployment settings.

## Capabilities

### New Capabilities

- `http-responses` defines the shared browser-facing header contract.

## Impact

Health and discovery responses gain headers. The response bodies and status codes retain their existing contracts.
