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

### Requirement: Database-backed password login decision
The credential step SHALL return the same invalid-credentials decision for unknown accounts, absent passwords and mismatches while recording distinct audit reasons. It SHALL refuse inactive accounts after verifying the password. It SHALL check the current credential and enrollment before advancing a successful attempt.

#### Scenario: Enrolled account
- **WHEN** a valid password belongs to an active TOTP-enrolled account
- **THEN** the service records a successful MFA challenge and returns a short-lived challenge without creating a session

#### Scenario: Additional login policy
- **WHEN** a valid password belongs to an active account without TOTP
- **THEN** the caller can continue the login transaction to evaluate further authentication requirements

### Requirement: Password attempt throttling
The login admission check SHALL charge each validated password attempt against a process-local source IP quota before looking up the account. Unresolved IPs SHALL share a quota. A positive limit SHALL allow that many immediate attempts and replenish evenly over one minute. A nonpositive limit SHALL disable throttling.

#### Scenario: Quota exhausted
- **WHEN** a caller has less than one attempt available
- **THEN** the check returns HTTP 429 with Retry-After of 60 seconds and records a rate-limited login failure for the attempted email

#### Scenario: Concurrent attempts
- **WHEN** simultaneous requests arrive for the same IP
- **THEN** each accepted attempt consumes a separate unit of available quota

### Requirement: Password login over HTTP
POST /api/v1/auth/login SHALL validate email and password, throttle by source and evaluate the first-party login policies. A completed login SHALL commit its session and logon audit together, then return the bearer token pair and the three session cookies. A challenged login SHALL return its method and pending credential without setting session cookies.

#### Scenario: Password login completes
- **WHEN** the account is active, the password matches and no second factor is due
- **THEN** the browser can immediately use the returned access cookie to read its current profile

#### Scenario: Required second factor
- **WHEN** TOTP or email confirmation is required
- **THEN** the response identifies the required method and holds the session until completion

#### Scenario: Stale access cookie
- **WHEN** password credentials are submitted with an existing access cookie
- **THEN** the handler authenticates the submitted credentials independently of the old session
