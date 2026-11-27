## Why

Authenticator enrollment confirmation, disablement and recovery-code replacement disagree on valid Unicode request encodings and on field diagnostics. In some cases clients receive field errors before their session is authenticated.

## What Changes

Use the existing session JSON decoder for authenticator proofs. Check session revocation before reporting field errors.

## Capabilities

### Modified Capabilities

- mfa-challenges

## Impact

Affects request validation on three existing first-party authenticator routes.
