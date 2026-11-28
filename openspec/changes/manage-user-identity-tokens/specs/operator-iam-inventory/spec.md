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

#### Scenario: Confirm a remote identity token status update

- **WHEN** the configured identity contract confirms the submitted status change
- **THEN** return the transaction hash in the provider's hexadecimal format after committing the user metadata and operator audit
- **WHEN** the transaction is mined but reverts
- **THEN** retain the previous stored status and record the failed outcome with the token identifier and requested status
- **WHEN** the contract confirms the update but the metadata and audit transaction fails to commit
- **THEN** return HTTP 500 and leave the confirmed contract update intact

#### Scenario: Identity status receipt deadline expires

- **WHEN** the provider has accepted a status transaction but its receipt remains pending through the deadline
- **THEN** return HTTP 200 with an unsuccessful result, null transaction hash and empty error string, and record the failed outcome
- **AND** retain the previous stored status even if the transaction later confirms on chain

#### Scenario: Remote mint retry confirms on the identity contract

- **WHEN** a mint retry confirms and the first identity-contract log carries a hexadecimal text token ID
- **THEN** return the confirmed transaction hash and preserve the full integer token ID in the response, user metadata and operator audit
- **AND** accept unsigned 256-bit values represented with surrounding ASCII whitespace, an optional sign, a hexadecimal prefix or valid underscore separators, including signed zero
- **WHEN** the confirmed receipt has no logs
- **THEN** report a successful mint with its transaction hash and a null token ID
- **WHEN** the provider rejects minting or the first log contains an invalid integer
- **THEN** return the failed provider result and persist the mint error with its operator audit

#### Scenario: Stored wallet name cannot be encoded for minting

- **WHEN** an operator retries a remote mint with a stored wallet name
- **THEN** return HTTP 200 with the provider's failed mint result and record its diagnostic in the user metadata and audit
- **AND** reject malformed name syntax before reading the pending nonce, and report encoding failures for accepted names after the nonce lookup and before submission
