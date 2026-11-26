## Why
A login can begin before a deployment switches backends and finish afterwards. Both services need to understand the pending second-factor credential.

## What Changes
Issue and verify signed, short-lived MFA challenges for password, passkey and email-link flows.

## Capabilities
### New Capabilities
- mfa-challenges
