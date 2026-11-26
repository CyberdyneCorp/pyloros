## Why
Moving sign-in to Rust requires verifying account credentials already in storage.

## What Changes
Provide a bounded verifier for stored account passwords and reuse its work queue for OAuth secret checks.

## Capabilities
### New Capabilities
- account-passwords
