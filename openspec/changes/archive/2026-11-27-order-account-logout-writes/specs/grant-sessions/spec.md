## ADDED Requirements

### Requirement: Coordinate logout with account erasure

Account-wide logout SHALL revoke visible sessions before advancing the account cutoff and SHALL commit session revocations, cutoff and audit together.

#### Scenario: Accepted logout overlaps account deletion

- **WHEN** both operations have admitted their callers and contend for the same open session
- **THEN** both operations can complete, the account is erased and its refresh credentials are refused
