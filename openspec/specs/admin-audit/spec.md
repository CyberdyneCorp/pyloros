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
