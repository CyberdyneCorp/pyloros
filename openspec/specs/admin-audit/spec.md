# admin-audit Specification

## Purpose
Give administrators a searchable record of privileged operations and their actors.

## Requirements

### Requirement: Browse administrative audit events
Pyloros SHALL return paginated audit history to a first-party administrator, ordered from newest to oldest.

#### Scenario: Find changes to a target
- **WHEN** an administrator filters by action, actor user, actor client, target type or target identifier
- **THEN** return events satisfying all supplied filters and the matching total before pagination

#### Scenario: Display an event
- **WHEN** the directory returns an event
- **THEN** include its stored actor identity, action, target, structured metadata, originating IP address and creation time

### Requirement: Verify retained audit history
Pyloros SHALL let a first-party administrator check the content hashes and linkage of retained audit events and return the result without changing the audit log.

#### Scenario: Intact retained history
- **WHEN** the log is empty or all retained records form one valid chain
- **THEN** return HTTP 200 with a valid verdict and the count examined

#### Scenario: Altered content or broken links
- **WHEN** a retained record has changed or the retained records no longer form one chain
- **THEN** return HTTP 200 with an invalid verdict, the row count and a diagnostic, identifying the record for a content mismatch
