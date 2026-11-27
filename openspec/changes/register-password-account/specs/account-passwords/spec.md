## ADDED Requirements

### Requirement: Register a password account
The service SHALL register an unverified account with a normalized email address, a password hash and an independently generated managed wallet.

#### Scenario: New account
- **WHEN** a validated, admitted registration supplies an unused email address
- **THEN** return the new account identifier, normalized email, uncompressed public key and checksummed wallet address, and email a single-use verification code.

#### Scenario: Wallet coexistence
- **WHEN** either deployment reads a newly registered account with the same master key
- **THEN** its decrypted 32-byte private key derives the stored public key and wallet address.

#### Scenario: Existing account
- **WHEN** registration encounters an email already registered, including through a concurrent request
- **THEN** return a conflict and preserve the existing account.

#### Scenario: Registration integrations
- **WHEN** a registration has matching webhook subscriptions and hooks
- **THEN** commit pending webhook deliveries with the account and dispatch hooks after commit.
