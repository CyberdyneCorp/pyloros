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
