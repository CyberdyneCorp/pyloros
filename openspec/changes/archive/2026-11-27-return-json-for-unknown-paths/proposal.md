## Why
Clients receive an empty response when they request an unknown URL and cannot read the usual error document.

## What Changes
Use the standard not-found response when an incoming URL and its canonical path both lack a route.

## Capabilities
### Modified Capabilities
- `http-responses` specifies the fallback error representation.

## Impact
This applies to HTTP routing before endpoint dispatch.
