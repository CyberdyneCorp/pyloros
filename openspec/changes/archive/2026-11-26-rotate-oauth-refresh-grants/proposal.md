## Why

Clients need to keep their existing OAuth sessions when traffic moves between the reference and Rust.

## What Changes

Support grant_type=refresh_token on the shared token endpoint. Preserve authorization, rotation and replay behavior across a backend switch.

## Impact

Reads client registration, current permissions, resource policy and session state. Updates the shared refresh-token family and records the grant outcome.
