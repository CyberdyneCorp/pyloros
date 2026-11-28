## ADDED Requirements

### Requirement: Commit each recovery email request independently
For an eligible address, the service SHALL issue a distinct recovery credential for each admitted request and record the successful request in the same transaction.

#### Scenario: Two writers issue recovery email concurrently
- **WHEN** two writers accept overlapping requests for the same address and both transactions commit
- **THEN** the recipient receives two distinct credentials, each matching a stored unused token for that account

#### Scenario: SMTP refuses the recipient
- **WHEN** the relay refuses a known recipient during submission
- **THEN** return HTTP 500 and roll back the recovery credential and successful request audit

#### Scenario: Commit rejected after delivery
- **WHEN** the relay accepts the email and PostgreSQL explicitly rejects the request at commit
- **THEN** return HTTP 500, preserve the previous credential and audit state, and reject the discarded link on redemption
