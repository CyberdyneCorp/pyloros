## ADDED Requirements

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
