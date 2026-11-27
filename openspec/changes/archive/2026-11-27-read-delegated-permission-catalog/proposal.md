## Why

Service clients need to discover the permissions they can assign.

## What Changes

Expose the calling client’s permission catalog through the REST API.

## Capabilities

### New Capabilities
- `delegated-permission-catalog`: Service-client permission discovery.

## Impact

Reuses the registered clients and permission tables.
