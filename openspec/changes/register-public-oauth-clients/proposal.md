## Why

Applications that discover the issuer and register at runtime need to keep working when registration or subsequent sign-in requests move between the two backends.

## What Changes

Implement the public client registration endpoint and its discovery feature gate. Apply issuer policy for redirect URIs, client authentication, grant types and scopes.

## Impact

A successful request adds a PostgreSQL client and its administrative audit record. Existing consent, authorization and token endpoints consume that registration.
