## ADDED Requirements

### Requirement: Manage a user's identity token

Authorized operators SHALL be able to retry issuance for a user's wallet and update a minted token's status through the configured provider.

#### Scenario: Retry issuance

- **WHEN** an operator retries issuance for a user with a wallet address and public key
- **THEN** report the provider outcome, persist the outcome on the user, and audit the attempt

#### Scenario: Missing wallet

- **WHEN** a retry targets an existing user without the required wallet or key
- **THEN** report the unsuccessful attempt and record the operator audit

#### Scenario: Change an existing token

- **WHEN** a token status change succeeds
- **THEN** record the change and expose the new status through the user token read

#### Scenario: Mint on the deployed chain

- **WHEN** preparing an identity token mint
- **THEN** send an empty email field to the identity contract

#### Scenario: Read a token using deployment settings

- **WHEN** a user has a token identifier and the identity provider is configured through deployment settings alone
- **THEN** obtain the token status from the deployed identity contract
- **AND** prefer a configured runtime provider when one is available

#### Scenario: Reload the local identity provider

- **WHEN** an operator reapplies blockchain settings while using the local provider
- **THEN** the new provider starts its token sequence at one
- **AND** the user token read continues to expose previously stored metadata

#### Scenario: User metadata changes during a mint retry

- **WHEN** a retry loads user metadata, a concurrent edit commits, and the provider returns an outcome for that retry
- **THEN** persist the retry result against the originally loaded metadata, even when doing so overwrites the intervening metadata edit
- **AND** commit the operator audit and metadata change together

#### Scenario: Audit failure after a local status change

- **WHEN** the provider changes an issued token's status and storing the operator audit fails
- **THEN** roll back the user's metadata update and return an internal error
- **AND** subsequent token reads expose the status already applied by the provider

#### Scenario: Unknown local token

- **WHEN** an operator requests a status change for an integer token identifier absent from the local provider
- **THEN** report an unsuccessful provider outcome and audit the original integer identifier at full precision

#### Scenario: Invalid mint recipient

- **WHEN** a deployed mint retry encounters a malformed hexadecimal recipient before transaction preparation
- **THEN** return the argument failure as the mint outcome and audit it
- **AND** for a full-length address with an invalid checksum, a pending nonce lookup failure takes precedence over the checksum error

#### Scenario: Provider returns a structured error

- **WHEN** the identity provider reports an RPC error during transaction preparation
- **THEN** preserve the provider's field order and integer precision in the operator-facing failure detail

#### Scenario: Provider request fails before submission

- **WHEN** transaction preparation encounters an HTTP refusal or a malformed provider response
- **THEN** report the failed provider outcome to the operator and record the audit
- **AND** include the provider failure detail in the mint retry outcome stored on the user
