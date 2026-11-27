## ADDED Requirements

### Requirement: Manage the account's active passkeys
The service SHALL restrict inventory operations to a first-party credential with a live session owned by the active account.

#### Scenario: List enrolled passkeys
- **WHEN** the feature is enabled and an eligible account requests its inventory
- **THEN** return active credentials for the configured relying party ordered by creation time, including only the record ID, name, timestamps and backup flags, with caching disabled.

#### Scenario: Manage an enrolled credential
- **WHEN** the account renames or revokes a credential
- **THEN** restrict the change to an active credential for that account and relying party. Revocation requires recent authentication and an alternative sign-in method.

#### Scenario: Rename an active credential
- **WHEN** an eligible account submits a name of one to 64 characters that contains visible text after trimming whitespace
- **THEN** save the trimmed display name and return the updated metadata. Return HTTP 404 for a missing, revoked, foreign-account or other relying-party credential.

#### Scenario: Simultaneous removal of the last credentials
- **WHEN** two requests try to revoke the only remaining sign-in credentials for one account
- **THEN** serialize recovery checks so at least one method remains, and commit a successful revocation and its audit record together.
