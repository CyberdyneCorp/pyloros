## ADDED Requirements

### Requirement: Validate and deliver account mailboxes

The service SHALL accept an unquoted local part longer than 64 bytes when the complete address remains within the 254-byte limit and satisfies account address syntax. Account mail delivery SHALL support these validated recipients. Validation SHALL reject unsafe Unicode, invalid ASCII and quoted local parts.

#### Scenario: Register and verify a long mailbox

- **WHEN** a valid long address is submitted for registration and the configured relay accepts its verification email
- **THEN** persist the account and allow the emailed credential to be redeemed.

#### Scenario: Disallowed characters before the domain

- **WHEN** a submitted local part includes a disallowed control or formatting character
- **THEN** report a validation error before consuming an allowance or sending mail.
