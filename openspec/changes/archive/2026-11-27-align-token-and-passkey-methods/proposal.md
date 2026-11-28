## Why
Method dispatch affects both the information clients receive for an unsupported token request and whether a passkey edit reaches the credential handler.

## What Changes
Return the normal method error document at the token exchange endpoint. Route PATCH and DELETE at the capabilities URL through the passkey modification handler.

## Capabilities
### Modified Capabilities
- `oauth-token` specifies method errors.
- `passkey-management` specifies the overlap between discovery and credential paths.

## Impact
Two existing URL paths change their responses to methods other than their discovery or exchange operations.
