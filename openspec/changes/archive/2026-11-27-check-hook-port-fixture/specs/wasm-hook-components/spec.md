## ADDED Requirements

### Requirement: Check a hook port against an offline fixture
The executable SHALL check a local component and JSON event against an expected guest success or guest error with exact text output using the isolated worker, without a database connection.

#### Scenario: A reviewed outcome matches
- **WHEN** the component returns the expected status and exact output for the supplied event
- **THEN** the check exits successfully and prints the SHA-256 of the checked artifact

#### Scenario: A port cannot be verified
- **WHEN** the fixture is invalid, the worker fails, or the guest outcome differs
- **THEN** the check exits unsuccessfully without printing event or output contents
