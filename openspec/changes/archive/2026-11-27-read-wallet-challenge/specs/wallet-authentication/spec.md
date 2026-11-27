## ADDED Requirements

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
