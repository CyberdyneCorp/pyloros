## Why
An issuer can serve more than one public origin. Token consumers and browser continuations need the correct origin behind a trusted reverse proxy.
## What Changes
Resolve the OIDC public base per request when no fixed issuer is configured. Keep session signing identity independent of the public request host.
## Capabilities
### Modified Capabilities
- issuer-discovery
## Impact
Discovery, device verification URLs, browser sign-in, code grants and refresh.
