## ADDED Requirements

### Requirement: Report a rejected passkey rename
The service SHALL return HTTP 500 when PostgreSQL explicitly rejects a passkey rename at commit.

#### Scenario: Retry a rename after rollback
- **WHEN** PostgreSQL rejects the rename transaction at commit
- **THEN** account and administrator inventories continue to show the original name, and a later successful rename returns the committed metadata
