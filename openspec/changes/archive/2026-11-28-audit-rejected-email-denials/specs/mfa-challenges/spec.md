## ADDED Requirements

### Requirement: Retain the recipient's refusal after a rejected denial
The service SHALL attempt to record a valid recipient's refusal in a separate audit write when PostgreSQL explicitly rejects the challenge denial at commit.

#### Scenario: Denial transaction rolls back
- **WHEN** a pending link matches and its conditional update succeeds but PostgreSQL rejects commit
- **THEN** return HTTP 500, keep the challenge pending and record the user's failed magic-link decision with reason `denied` when the audit store is available
- **AND** a later successful denial records the new decision and prevents session issuance
