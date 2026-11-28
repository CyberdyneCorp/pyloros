## ADDED Requirements

### Requirement: Bcrypt recovery cohort inventory
Operators SHALL be able to request a read-only inventory of bcrypt-prefixed accounts grouped by active status and presence of a nonblank primary email. The report SHALL return four counts including zeroes and use the same bcrypt prefix classification as the default family inventory.

#### Scenario: Missing primary email
- **WHEN** an active bcrypt account has a null, empty or whitespace-only primary email
- **THEN** it contributes to the active count without email

#### Scenario: Password scheme changes
- **WHEN** a bcrypt credential is replaced with Argon2
- **THEN** reports from other connections exclude that account from its previous cohort only after commit
