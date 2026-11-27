## ADDED Requirements

### Requirement: Manage the account's active passkeys
The service SHALL restrict inventory operations to a first-party credential with a live session owned by the active account.

#### Scenario: List enrolled passkeys
- **WHEN** the feature is enabled and an eligible account requests its inventory
- **THEN** return active credentials for the configured relying party ordered by creation time, including only the record ID, name, timestamps and backup flags, with caching disabled.

#### Scenario: Manage an enrolled credential
- **WHEN** the account renames or revokes a credential
- **THEN** restrict the change to an active credential for that account and relying party. Revocation requires recent authentication and an alternative sign-in method.
