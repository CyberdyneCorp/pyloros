## Why

A sign-out request with a valid body can still fail when PostgreSQL rejects the session revocation.

## What Changes

Qualify the logout success response and specify how the browser recovers from an explicit commit rejection.

## Capabilities

### Modified Capabilities
- `grant-sessions` covers the session and cookie effects of a rejected logout.

## Impact

Clients can retry sign-out with the existing session after HTTP 500.
