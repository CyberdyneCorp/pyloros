## ADDED Requirements

### Requirement: Inspect a user's active passkeys

The service SHALL allow administrators to read the active passkeys for a specified user across relying parties, independently of the sign-in feature setting.

#### Scenario: Render the inventory

- **WHEN** an authorized operator requests credentials for an existing user
- **THEN** return their active credentials oldest first with the identifier, label, relying party, timestamps and backup flags, and mark the response no-store.

#### Scenario: Distinguish an empty account from a missing one

- **WHEN** the user exists with no active passkeys
- **THEN** return an empty list.
- **WHEN** the user does not exist
- **THEN** return the user-not-found error.
