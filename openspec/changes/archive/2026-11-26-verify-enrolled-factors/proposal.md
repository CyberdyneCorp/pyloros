## Why
Accounts with enrolled authenticators must retain their existing TOTP and backup codes through the backend migration.
## What Changes
Add transactional verification for encrypted TOTP seeds and single-use recovery codes.
## Capabilities
### Modified Capabilities
- mfa-challenges
