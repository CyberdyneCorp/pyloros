## Why

Large encoded requests are rejected before session validation. Numeric values outside the native JSON representation can be mistaken for omitted refresh credentials.

## What Changes

Use the common request decoder and exact scalar validation on the four first-party session routes.

## Capabilities

### Modified Capabilities

- grant-sessions

## Impact

Affects login, MFA verification, refresh and single-session logout.
