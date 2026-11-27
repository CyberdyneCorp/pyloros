## ADDED Requirements

### Requirement: Export data belonging to a subject
The service SHALL provide a first-party account export and an administrator export for a specified account. It SHALL identify the subject using the account and its linked identity records. Invalid identity metadata SHALL fail the operation before producing a download or modifying personal data.

#### Scenario: Request an account download
- **WHEN** an eligible caller exports an existing account
- **THEN** return an uncached JSON attachment with its section inventory, retention information and relevant external processors, and audit the number of sections and rows

#### Scenario: Bound the export
- **WHEN** a section has more than 1,000 matching records
- **THEN** return 1,000 records for the section and mark it truncated

#### Scenario: Protect sensitive data
- **WHEN** a record contains credentials, binary secrets or another person's identifiers in a shared authentication event
- **THEN** restrict the export to its approved fields and redact the other person's subject identifiers or connection details as applicable

#### Scenario: Limit repeated downloads
- **WHEN** a subject consumes the self-service allowance of three exports per hour
- **THEN** return the rate-limit response on further attempts until quota is available
