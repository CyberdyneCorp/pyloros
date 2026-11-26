## Why
The shared dashboard needs an authenticated session probe that returns the current user's profile.

## What Changes
Implement the self-service profile read with signed access credentials, optional revocation checks and live PostgreSQL account data.

## Impact
GET /api/v1/users/me and the access-token verification configuration.
