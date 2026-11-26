## Why
A claimed grant needs a single issuance operation for a consistent token response.

## What Changes
Assemble the session and scoped response within the caller's PostgreSQL transaction.

## Impact
Grant-session library and public specification.
