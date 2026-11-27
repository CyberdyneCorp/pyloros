## Why
Deployments using a shared session signing secret need discovery and ordinary OAuth authorization-code grants during migration.

## What Changes
Support discovery and OAuth code exchange with a configured issuer and HS256 session signing. Reserve ID token issuance for RS256.

## Capabilities
### Modified Capabilities
- issuer-discovery
- grant-sessions

## Impact
Provider startup, key publication and token exchange.
