## ADDED Requirements

### Requirement: Email recipient inspection and decision
The inspect, confirm and deny endpoints under /api/v1/auth/magic-link SHALL authenticate the submitted link token and share a per-source quota. Only a pending unexpired link SHALL reveal the match code, timestamps and originating device details. Inspection SHALL set Cache-Control to no-store and leave the challenge pending.

#### Scenario: Recipient decides
- **WHEN** the holder confirms or denies a pending link
- **THEN** exactly one decision succeeds, returns 204, and is recorded in the audit trail

#### Scenario: Used or expired link
- **WHEN** the supplied token has expired or already received a decision
- **THEN** inspection and decision return the invalid-link error without revealing the original challenge
