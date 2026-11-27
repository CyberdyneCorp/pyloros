## ADDED Requirements

### Requirement: Email password recovery
The service SHALL accept an email address for password recovery and allow the owner to redeem a valid emailed credential once.

#### Scenario: Request recovery
- **WHEN** an admitted caller submits a valid address
- **THEN** return the same empty success response for known and unknown accounts and deliver a time-limited credential only to the registered address.

#### Scenario: Redeem the credential
- **WHEN** the owner submits an unused, unexpired credential and a valid replacement password
- **THEN** replace the password, verify the email, assign an eligible domain organization to an unaffiliated account, invalidate existing sessions, consume the credential and record the successful outcome.

#### Scenario: Invalid credential
- **WHEN** a credential is unknown, expired or already consumed
- **THEN** reject the reset without altering the account and record the refusal.

#### Scenario: Concurrent redemption
- **WHEN** two callers redeem the same credential simultaneously
- **THEN** at most one password replacement commits.

#### Scenario: Browser retains a stale session cookie
- **WHEN** a browser requests or confirms a reset with an old access cookie
- **THEN** evaluate the reset request independently of that cookie.
