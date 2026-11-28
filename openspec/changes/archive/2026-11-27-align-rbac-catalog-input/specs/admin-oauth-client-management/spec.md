## ADDED Requirements

### Requirement: Decode catalog entry creation requests
The operator and delegated client role and permission creation routes SHALL accept UTF-8, UTF-16 and UTF-32 documents larger than two MiB. The service SHALL validate the submitted key and description before saving the entry.

#### Scenario: Unicode catalog description
- **WHEN** an authorized caller submits a valid entry in a padded Unicode document
- **THEN** create the entry and preserve its description on subsequent reads

#### Scenario: Unrelated numeric field
- **WHEN** a valid entry includes an ignored field containing a non-finite number
- **THEN** create the entry using the recognized fields

#### Scenario: Non-finite description
- **WHEN** an authorized caller supplies a non-finite number as the description
- **THEN** return the reference HTTP 500 response for an unrepresentable validation error and leave the catalog unchanged
