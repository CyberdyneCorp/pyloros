## ADDED Requirements

### Requirement: Confirm email verification only after commit
The service SHALL return HTTP 500 when PostgreSQL explicitly rejects a valid email confirmation at commit. The code consumption, account verification, domain membership changes and success audit SHALL roll back together.

#### Scenario: Retry an emailed code after rollback
- **WHEN** a valid, unexpired code is retried after the rejected transaction and the database accepts the new transaction
- **THEN** return HTTP 204, consume the code, verify the account, apply any eligible domain membership and record one successful verification
- **AND** a later replay returns HTTP 400.
