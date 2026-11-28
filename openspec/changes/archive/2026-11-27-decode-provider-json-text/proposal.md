## Why
Provider documents can arrive as Unicode JSON with a byte order mark or a wide encoding. Federated sign-in should read these representations consistently at both stages of the exchange.

## What Changes
Decode JSON text after HTTP decompression for the token and profile endpoints.

## Capabilities
### Modified Capabilities
- external-oauth

## Impact
Affects external provider response parsing.
