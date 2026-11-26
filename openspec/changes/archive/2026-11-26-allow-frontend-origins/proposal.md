## Why
The shared frontend calls the API with credentials from its own origin.

## What Changes
Apply the configured browser origin policy to API responses and preflight requests.

## Impact
Global HTTP middleware and the PostgreSQL origin registry.
