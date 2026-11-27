## Why

Credential consumers currently disagree on numeric input errors and unrelated numeric fields in otherwise valid JSON.

## What Changes

Use the same scalar document decoder for emailed credentials, recovery and sign-in requests.

## Capabilities

### Modified Capabilities
- account-passwords
- mfa-challenges

## Impact

Email verification, password recovery and magic-link request decoding.
