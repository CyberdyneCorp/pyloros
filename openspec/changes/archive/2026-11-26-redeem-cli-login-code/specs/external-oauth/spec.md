## ADDED Requirements

### Requirement: Redeem a CLI login code

The service SHALL accept a JSON code and verifier at POST /api/v1/auth/cli/exchange, subject to the CLI feature switch and login rate limit.

#### Scenario: Complete a CLI login

- **WHEN** an active account's current code is presented with its matching S256 verifier
- **THEN** issue one federated session, record a successful token grant and return access and refresh tokens, bearer type and access lifetime.

#### Scenario: Refuse credentials

- **WHEN** a code is unknown, expired, already used, presented with an incorrect verifier, or bound to an ineligible account
- **THEN** return HTTP 400 with the same invalid_grant response and record the refusal. A current code presented with an incorrect verifier or ineligible account is consumed.

#### Scenario: Concurrent redemption

- **WHEN** two callers redeem one valid code concurrently
- **THEN** at most one receives tokens and only one session is created.

#### Scenario: Validate input before redemption

- **WHEN** the submitted JSON lacks the required string fields, contains an empty code or exceeds either field's 128-character limit
- **THEN** respond with HTTP 400 and the invalid_grant error before claiming any code. An empty verifier on a valid code reaches the proof check and consumes the code.

#### Scenario: Session storage fails

- **WHEN** a valid exchange cannot persist its session
- **THEN** roll back the code claim so the CLI can retry.
