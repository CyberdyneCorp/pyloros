## Why

New accounts need to sign up through the existing registration contract during the migration.

## What Changes

Accept email and password registrations, provision the account wallet and deliver the email verification credential. Preserve registration audit, webhook and hook behavior.

## Capabilities

### Modified Capabilities

- `account-passwords` supports public account registration.

## Impact

Registration writes PostgreSQL account and verification state and integrates with the existing mail and event systems.
