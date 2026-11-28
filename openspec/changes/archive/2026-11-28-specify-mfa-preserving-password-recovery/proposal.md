## Why

A bcrypt account can already have an enrolled authenticator and partially used recovery codes. Operators need a predictable path to replace its password while retaining its second factor.

## What Changes

Specify enrollment continuity for the existing operator password reset when moving an account to Argon2.

## Impact

Clarifies the account-passwords specification and recovery guidance. The existing API and schema support this flow.
