## ADDED Requirements

### Requirement: Preserve administrative session revocation across a drained writer switch
After a writer switch the incoming service SHALL honor the committed refresh and revocation state of an existing login session.

#### Scenario: Rotation completes on the outgoing writer
- **WHEN** refresh commits before the handoff and an administrator revokes the session on the incoming writer
- **THEN** the rotated credential is refused on refresh, the session has no active refresh records, and the revocation produces one operator audit entry

#### Scenario: Revocation completes on the outgoing writer
- **WHEN** an administrator revokes the session before the handoff and its refresh credential is presented to the incoming writer
- **THEN** refresh is refused and the committed revocation audit remains the only revocation entry for that request
