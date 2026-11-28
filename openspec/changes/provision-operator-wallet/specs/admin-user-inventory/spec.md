## ADDED Requirements

### Requirement: Administrator managed wallet provisioning

The service SHALL allow an authenticated administrator to provision a managed wallet for an existing account. The response SHALL identify the user and wallet address and indicate whether the operation created the wallet.

#### Scenario: Account without an address

- **WHEN** the administrator provisions a wallet for a user with a missing or empty address
- **THEN** persist the generated public key, encrypted private key and corresponding address and record the provisioning audit event in the same transaction

#### Scenario: Existing address

- **WHEN** the account already has a nonempty address
- **THEN** return that address with the creation flag cleared and preserve its stored keys and audit history

#### Scenario: Unknown user

- **WHEN** the administrator provides a valid identifier for an absent account
- **THEN** return HTTP 404

#### Scenario: Historical metadata

- **WHEN** wallet provisioning encounters historical user metadata stored as key-value pairs
- **THEN** normalize valid pairs when saving new keys, preserve the original representation on an existing-wallet read, and fail the operation on malformed pairs

#### Scenario: Overlapping first-time provision requests

- **WHEN** two authorized requests both read the account before either wallet write commits
- **THEN** each successful request returns its generated address and appends an audit event, and the final committed write determines the stored keys

#### Scenario: Existing address during a replica configuration mismatch

- **WHEN** an operator provisions an account that already has a wallet through a replica configured with a different encryption key from the writer
- **THEN** return the original address with `created=false` and preserve the stored key material, account revision and provisioning audit history.
