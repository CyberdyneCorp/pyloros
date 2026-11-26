# account-passwords Specification

## Purpose
Verify stored account credentials before deciding whether sign-in requires a second factor or a new session.

## Requirements

### Requirement: Verify existing account passwords
The password verifier SHALL support Argon2 and bcrypt under explicit scheme selection, using Argon2 by default. Missing credentials SHALL incur a synthetic check for the selected scheme and always fail. Account and OAuth credential verification SHALL share a process-wide concurrency limit.

#### Scenario: Existing credential
- **WHEN** the supplied password matches a valid stored hash in the selected scheme
- **THEN** password verification succeeds

#### Scenario: Invalid credential
- **WHEN** the stored credential is absent, malformed, or belongs to a different scheme
- **THEN** password verification fails
