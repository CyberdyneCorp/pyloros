## ADDED Requirements

### Requirement: Verify retained audit history
Pyloros SHALL let a first-party administrator check the content hashes and linkage of retained audit events and return the result without changing the audit log.

#### Scenario: Intact retained history
- **WHEN** the log is empty or all retained records form one valid chain
- **THEN** return HTTP 200 with a valid verdict and the count examined

#### Scenario: Altered content or broken links
- **WHEN** a retained record has changed or the retained records no longer form one chain
- **THEN** return HTTP 200 with an invalid verdict, the row count and a diagnostic, identifying the record for a content mismatch
