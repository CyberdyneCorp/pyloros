## ADDED Requirements

### Requirement: Report the stored settings for each hook port
The read-only binding inventory SHALL include the stored timeout in seconds, network permission and personal data opt-in for each hook.

#### Scenario: Review selected and unselected hooks
- **WHEN** the operator checks binding coverage
- **THEN** each row includes its timeout_seconds, allow_network and receive_pii values alongside its digests

#### Scenario: Read a historical schema
- **WHEN** the hooks table lacks one or more settings columns
- **THEN** return null for each missing setting and retain the values of the available settings
