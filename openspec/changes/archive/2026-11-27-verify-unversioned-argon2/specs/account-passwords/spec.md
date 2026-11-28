## ADDED Requirements

### Requirement: Read historical Argon2 credentials
The verifier SHALL interpret an omitted version field in a stored Argon2 credential as version 16 for both account passwords and OAuth client secrets.

#### Scenario: Historical version omitted
- **WHEN** a correct secret is submitted for an Argon2i, Argon2d or Argon2id version 16 hash with no version field
- **THEN** verification succeeds

#### Scenario: Version explicitly recorded
- **WHEN** the stored hash specifies a version
- **THEN** verification uses that version and rejects a digest that does not match it
