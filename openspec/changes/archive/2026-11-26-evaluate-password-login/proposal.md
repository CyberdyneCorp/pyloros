## Why
Browser sign-in needs a database-backed decision before it can start a second factor or create a session.

## What Changes
Check stored account credentials and activity, audit refusals, and issue an audited challenge when TOTP is enabled.

## Capabilities
### Modified Capabilities
- account-passwords
