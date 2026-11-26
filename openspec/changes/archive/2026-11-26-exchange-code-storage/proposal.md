## Why

During issuer migration either service may receive the code exchange. Both must recognize the same grant facts and agree on its single-use state.

## What Changes

Add a PostgreSQL adapter for issuing, finding and claiming authorization codes in caller-owned transactions.

## Capabilities

### New Capabilities

- `authorization-code-storage` covers persistence and transactional claim semantics.

## Impact

The token endpoint will use this adapter after authenticating the client and checking the grant. This increment adds no HTTP endpoint.
