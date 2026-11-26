## Why
Password login must honor the stored email confirmation policy when an account has no TOTP enrollment.

## What Changes
Evaluate the policy in the login transaction, stage a pending link, and release a bound polling credential after delivery succeeds.
## Capabilities
### Modified Capabilities
- mfa-challenges
