## ADDED Requirements

### Requirement: Explicit database commit rejection
The service SHALL return HTTP 500 when PostgreSQL explicitly rejects the request transaction at commit. Responses that depend on that commit, including downloads with mandatory audit writes and session cookies, SHALL be released only after the transaction succeeds.

#### Scenario: Audited export rolls back
- **WHEN** a deferred constraint rejects the audit write for an account download at commit
- **THEN** the client receives HTTP 500 and no download

#### Scenario: Queued webhook rolls back
- **WHEN** PostgreSQL rejects the commit for an administrator's test delivery
- **THEN** the client receives HTTP 500 and the queue and audit history retain their previous state
