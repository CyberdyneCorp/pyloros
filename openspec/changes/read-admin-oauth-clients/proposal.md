## Why

Operators using the existing admin console and CLI need to inspect registered applications during a backend transition.

## What Changes

Serve the administrative OAuth client collection and client detail from PostgreSQL. Preserve operator authorization, pagination, filtering and the public representation of each client.

## Impact

The change introduces authenticated administrative reads against existing client records.
