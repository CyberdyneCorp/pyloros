## Why

Relying parties need a signed identity assertion when a user consents to OpenID Connect.

## What Changes

Issue RS256 ID tokens for OpenID grants with issuer, client audience, subject, timing, browser authentication context and scope-dependent claims.

## Capabilities

### Modified Capabilities

- `grant-sessions` adds ID-token issuance.

## Impact

The exchange service can sign ID tokens using the same issuer key as refresh credentials.
