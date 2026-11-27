## ADDED Requirements

### Requirement: Issue a wallet sign-in challenge

The service SHALL issue a challenge without authenticating the caller. It SHALL validate the wallet address and chain identifier before consuming the caller's challenge quota. A successful response SHALL include a unique challenge identifier, a random nonce, the exact message to sign and the configured lifetime.

#### Scenario: Challenge issued

- **WHEN** a caller submits a valid Ethereum address
- **THEN** return HTTP 201 with the signing message and persist a pending challenge containing that message, the normalized address, chain identifier, nonce and expiration
- **AND** preserve the submitted address casing in the message

#### Scenario: Rate limit reached

- **WHEN** a source exhausts its challenge quota
- **THEN** return HTTP 429 with a retry interval and leave the challenge inventory unchanged

#### Scenario: Invalid input

- **WHEN** the wallet address or chain identifier fails request validation
- **THEN** return the field validation errors before checking the rate limit

#### Scenario: Persistence failure

- **WHEN** PostgreSQL rejects the challenge insert
- **THEN** return the internal-error response and consume the validated request's quota unit

#### Scenario: Commit-time failure

- **WHEN** the insert succeeds and PostgreSQL rejects the transaction at commit
- **THEN** return the issued challenge document and allow its subsequent lookup to report it missing
