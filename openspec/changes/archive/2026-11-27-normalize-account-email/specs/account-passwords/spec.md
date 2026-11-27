## ADDED Requirements

### Requirement: Normalize internationalized account email

The service SHALL normalize the local part of an accepted account address to NFC and use the lowercase Unicode form of its internationalized domain before account lookup and creation.

#### Scenario: Recovery with an equivalent domain spelling

- **WHEN** a client submits the ASCII IDNA spelling of a registered internationalized domain
- **THEN** issue recovery for the same stored account as a request using the Unicode spelling.

#### Scenario: Decomposed local part

- **WHEN** a client submits an accepted local part with canonically decomposed characters
- **THEN** use its canonically composed spelling while preserving local-part case.
