## Why

Clients encounter different validation responses depending on the encoding or media type used for the same session operation.

## What Changes

Use the common JSON document and field validation for first-party sign-in, MFA, refresh and logout. Keep cookie precedence, the existing body size limit and session behavior.

## Capabilities

### Modified Capabilities

- `grant-sessions` specifies the session request decoding contract.

## Impact

Changes request decoding and error responses before credential verification.
