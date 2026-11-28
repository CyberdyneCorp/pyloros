## ADDED Requirements

### Requirement: Validate the UUID URN prefix on typed fields
The shared REST UUID field validator SHALL accept the lowercase urn:uuid: prefix and reject case variants of that prefix.

#### Scenario: Read an account using a lowercase UUID URN
- **WHEN** an authorized caller uses a valid hyphenated user UUID with the lowercase URN prefix
- **THEN** resolve the same user as the unprefixed identifier

#### Scenario: Submit a case variant of the prefix
- **WHEN** a typed UUID field uses an uppercase or mixed-case URN prefix
- **THEN** return the usual uuid_parsing field error identifying the first character at position one

#### Scenario: Report the wrong final group length
- **WHEN** a braced or lowercase URN UUID has a final group of the wrong length after four correctly sized groups
- **THEN** include the submitted wrapper length in the reported final-group length
