## ADDED Requirements

### Requirement: Honor committed catalog capacity across writer changes
After a drained writer switch, role and permission creation SHALL use the committed global role or permission count for the client, regardless of whether the caller uses the administrator or delegated API.

#### Scenario: Outgoing writer commits the final key
- **WHEN** the incoming writer receives a different valid key after the outgoing writer fills the catalog
- **THEN** return HTTP 409 and preserve the committed catalog and audit

#### Scenario: Outgoing final key rolls back
- **WHEN** the outgoing creation rolls back and the incoming writer receives a valid new key
- **THEN** allow creation in the available slot and record the incoming caller's audit
