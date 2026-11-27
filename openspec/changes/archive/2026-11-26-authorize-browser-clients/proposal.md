## Why

Applications need to initiate an authorization-code flow against Pyloros and complete it on either deployment.

## What Changes

Implement browser authorization, hosted login continuation, session freshness, client and resource scope checks, consent and code issuance.

## Capabilities

### Modified Capabilities

- `oauth-token` gains the browser-facing authorization and consent operations.

## Impact

Browser requests read the OAuth client and resource registries. Successful authorization stores a single-use code in PostgreSQL.
