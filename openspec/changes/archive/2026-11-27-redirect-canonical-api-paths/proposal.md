## Why

Clients that retain the closing slash on an API URL need to reach the canonical route.

## What Changes

Redirect requests with trailing slashes to a registered path while preserving the query and request method.

## Capabilities

### Modified Capabilities
- `http-responses` covers canonical route redirects.

## Impact

The application router resolves alternate paths before responding to an unmatched request.
