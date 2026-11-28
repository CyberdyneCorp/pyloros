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

#### Scenario: Registration while hook migration is incomplete
- **WHEN** the Rust service receives a new registration with an active registration hook lacking a component binding
- **THEN** return HTTP 503 before sending verification email and roll back the new account and pending hook deliveries.

#### Scenario: Verify a registration after switching backends
- **WHEN** a registration succeeds with multiple matching hooks and its email verification code is presented to the other backend
- **THEN** verify the same account, allow sign-in there, and execute each registration hook once for the account.
- **AND** a duplicate registration returns a conflict without sending another verification email or dispatching more registration hooks.
