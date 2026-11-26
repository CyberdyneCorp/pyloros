## Why

Operators can update an issuer's scope catalog while its discovery replicas are serving requests.

## What Changes

Refresh active PostgreSQL scope names on each discovery replica and advertise them alongside its configured base scopes.

## Capabilities

### Modified Capabilities

- `issuer-discovery` adds background discovery scope refresh.

## Impact

Discovery requires read access to the registry table to advertise administrator-managed scopes.
