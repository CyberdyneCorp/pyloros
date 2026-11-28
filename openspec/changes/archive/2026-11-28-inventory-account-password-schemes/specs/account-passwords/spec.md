## ADDED Requirements

### Requirement: Count stored account password schemes
An operator SHALL be able to obtain aggregate counts of all accounts by stored password prefix in one read-only database snapshot. The report SHALL include Argon2, bcrypt, absent credentials and unrecognized values, with zero counts for empty categories. It SHALL return only these counts.

#### Scenario: Historical accounts coexist with migrated accounts
- **WHEN** the account table contains Argon2i, Argon2d, Argon2id, original bcrypt or bcrypt 2a, 2b or 2y prefixes
- **THEN** count each recognized prefix in its corresponding family
- **AND** count SQL NULL as absent and other values, including the empty string, as unrecognized

#### Scenario: Account completes recovery
- **WHEN** a bcrypt account receives a replacement Argon2 credential and the transaction commits
- **THEN** a subsequent report counts the account only under Argon2
