# wallet-authentication Specification

## Purpose
Define how wallet sign-in clients inspect issued challenges and observe their expiry in the shared account database.

## Requirements

### Requirement: Public wallet challenge status

The service SHALL allow a caller to look up a wallet sign-in challenge by identifier. It SHALL return the identifier, stored wallet address, status and remaining lifetime in whole seconds. Remaining lifetime SHALL have a lower bound of zero.

#### Scenario: Pending challenge expires

- **WHEN** a caller reads a pending challenge after its expiry time
- **THEN** persist the expired status and return zero remaining seconds

#### Scenario: Terminal status

- **WHEN** a caller reads a consumed, completed, failed or expired challenge
- **THEN** preserve its stored status and calculate its remaining lifetime

#### Scenario: Lookup failure

- **WHEN** the requested challenge is missing or its stored record cannot be read
- **THEN** return HTTP 404 with the challenge-not-found detail

#### Scenario: Invalid identifier

- **WHEN** the supplied path identifier is malformed
- **THEN** return the path validation error for the challenge identifier

#### Scenario: Deferred expiry write fails

- **WHEN** an expired challenge is successfully read and its status update fails during transaction commit
- **THEN** report the observed expired status and zero remaining seconds, and allow a subsequent read to retry persistence

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
