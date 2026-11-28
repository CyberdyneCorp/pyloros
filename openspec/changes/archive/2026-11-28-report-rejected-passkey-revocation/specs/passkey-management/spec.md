## ADDED Requirements

### Requirement: Report explicit rejection of a passkey revocation
The service SHALL return HTTP 500 when PostgreSQL explicitly rejects a passkey revocation at commit.

#### Scenario: Retry revocation after rollback
- **WHEN** a revocation fails at commit and the caller later retries after the failure clears
- **THEN** the credential stays active until the retry commits, and the credential activity history records one successful revocation
