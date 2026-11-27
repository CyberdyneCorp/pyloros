## ADDED Requirements

### Requirement: Verify account email
A caller SHALL be able to verify an account email by presenting an unused, unexpired verification credential without signing in.

#### Scenario: Confirm email ownership
- **WHEN** the caller supplies a valid credential
- **THEN** mark the email verified, consume the credential, record the outcome and return an empty 204. An unaffiliated account joins the active organization matching its email domain, including a membership row.

#### Scenario: Invalid or expired credential
- **WHEN** the credential is unknown, expired or previously consumed
- **THEN** return the same 400 error and audit the refusal without altering the account.

#### Scenario: Concurrent use
- **WHEN** multiple callers present the same credential concurrently
- **THEN** at most one verification succeeds.
