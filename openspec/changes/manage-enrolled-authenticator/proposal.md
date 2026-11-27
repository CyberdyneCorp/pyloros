## Why

Account owners need to replace lost backup codes and retire an authenticator through the existing preferences screen.

## What Changes

Add first-party operations for regenerating recovery codes and disabling an enrolled authenticator. Require fresh proof of account control and an unused authenticator code for either operation.

## Capabilities

### Modified Capabilities

- `mfa-challenges` gains management of active enrollments.

## Impact

The Rust HTTP service uses existing PostgreSQL credentials, sessions, passkey proofs and audit storage. Existing frontend clients use their current request and response formats.
