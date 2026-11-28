## ADDED Requirements

### Requirement: Honor client-bound refresh grants across a drained writer switch
The incoming service SHALL rotate a valid OAuth refresh credential issued by the outgoing writer with its session, client, consent and resource bindings preserved. It SHALL honor an administrator's committed revocation of that session.

#### Scenario: Rotate on both writers
- **WHEN** a client rotates its refresh grant before a drained switch and submits the replacement to the incoming writer
- **THEN** both rotations extend the same refresh family and only the latest credential remains active

#### Scenario: Submit a revoked grant to the incoming writer
- **WHEN** the client presents its latest credential after the administrator has revoked the session on either writer
- **THEN** the token endpoint returns HTTP 400 with the OAuth error `invalid_grant` and the family has no active refresh records
