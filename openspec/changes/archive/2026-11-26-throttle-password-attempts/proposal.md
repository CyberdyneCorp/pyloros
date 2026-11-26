## Why
A failed password attempt must count toward the source's sign-in quota before any expensive credential work starts.

## What Changes
Provide the login handler with per-source admission control, an audited refusal and the browser-facing retry response.

## Capabilities
### Modified Capabilities
- account-passwords
