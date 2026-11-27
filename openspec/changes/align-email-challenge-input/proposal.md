## Why

Recipients and initiating clients need consistent validation when sign-in traffic switches backends.

## What Changes

Use the same request decoding and exact field-error reporting for recipient tokens and status polling.

## Capabilities

### Modified Capabilities

- `mfa-challenges` gains request validation requirements for email challenges.

## Impact

Covers inspection, approval, denial and polling. The challenge state machine continues to own consumption and audit.
