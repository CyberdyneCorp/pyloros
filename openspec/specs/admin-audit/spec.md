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

### Requirement: Preserve authentication event cursor interpretation
Both authentication history listings SHALL interpret supported alternative cursor encodings identically.

#### Scenario: Alternative hexadecimal event identifier
- **WHEN** a cursor’s identifier contains 32 characters after wrapper and hyphen removal and represents a hexadecimal integer with Unicode decimal digits, a leading plus sign or valid underscore separators
- **THEN** continue at the decoded timestamp and numeric identifier and audit the successful read

#### Scenario: Week date exceeds the calendar
- **WHEN** the ISO week date in a cursor resolves beyond Gregorian year 9999
- **THEN** return the invalid cursor error before recording a successful read

### Requirement: Review authentication events
Pyloros SHALL let first-party administrators browse authentication activity globally or for a specified user, recording each successful read in the administrative audit log.

#### Scenario: Page through events
- **WHEN** an administrator requests a page
- **THEN** return events in descending time and identifier order with an opaque continuation cursor when more events match

#### Scenario: Investigate an authentication outcome
- **WHEN** the administrator combines subject, client, actor, outcome, activity, reason or time filters
- **THEN** return matching event records including their subject, actor, protocol, outcome, context and stored content hash

#### Scenario: Read one user's trail
- **WHEN** a user identifier scopes the directory
- **THEN** return events for that subject and identify the user as the target of the read audit, including when the directory is empty

#### Scenario: Database rejects the read audit at commit
- **WHEN** PostgreSQL explicitly rejects the audit transaction for a global or per-user directory read at commit
- **THEN** return HTTP 500 and withhold the event page
