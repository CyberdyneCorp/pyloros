## ADDED Requirements

### Requirement: Decode large role permission replacement documents
The operator and delegated role permission replacement endpoints SHALL process valid UTF-8, UTF-16 and UTF-32 JSON envelopes exceeding two MiB under the existing authentication and catalog rules.

#### Scenario: Padded replacement
- **WHEN** an authorized caller submits an otherwise valid mapping in a padded JSON envelope exceeding two MiB
- **THEN** return the replaced mapping and persist the selected permissions

#### Scenario: Unauthenticated replacement
- **WHEN** a caller without credentials submits a valid padded mapping
- **THEN** apply the same authentication response as for a compact mapping

#### Scenario: Invalid large mapping
- **WHEN** an authorized caller submits more than 256 permission entries in a padded document
- **THEN** return the list validation error and preserve the previous mapping
