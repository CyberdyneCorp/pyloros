## Why
Password changes accept international JSON clients and must report errors consistently with the credential APIs.

## What Changes
Decode the full credential document before authentication and validate its fields after authentication.

## Capabilities
### Modified Capabilities
- account-passwords

## Impact
Password change over HTTP.
