## ADDED Requirements

### Requirement: Download audit history
Pyloros SHALL allow a first-party administrator to download audit records as newline-delimited JSON with the content and links needed for offline verification.

#### Scenario: Export a time range
- **WHEN** the operator supplies a lower or upper creation-time bound
- **THEN** include the matching endpoints of the interval and order records by creation time and identifier

#### Scenario: Download the file
- **WHEN** an authorized operator starts a download
- **THEN** return an NDJSON attachment named `audit-log.ndjson`, with one complete JSON object and newline per exported event

#### Scenario: Read a historical infinite timestamp
- **WHEN** an exported event has a PostgreSQL infinite timestamp
- **THEN** use the corresponding calendar limit without a timezone suffix

#### Scenario: A later record cannot be exported
- **WHEN** the response has started and the service encounters unreadable history
- **THEN** finish the download with the complete records already emitted
