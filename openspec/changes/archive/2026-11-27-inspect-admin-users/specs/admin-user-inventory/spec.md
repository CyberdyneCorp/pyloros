## ADDED Requirements

### Requirement: Inspect accounts as an administrator

The service SHALL permit authorized operators to list users and inspect an individual account using the existing API.

#### Scenario: Search the directory

- **WHEN** an administrator filters the user directory
- **THEN** return the filtered total and a newest-first page, including identity counts and administrator status.
- **WHEN** search text contains wildcard characters
- **THEN** match the text literally in the email or wallet address.

#### Scenario: Inspect an account

- **WHEN** an administrator requests an existing user
- **THEN** return account metadata, linked identity summaries, bootstrap administrator status and the latest session activity.
- **WHEN** the user identifier is unknown
- **THEN** return the established not-found response.

#### Scenario: Protect user information

- **WHEN** the caller lacks administrative access
- **THEN** deny the request before disclosing account data or query validation details.
