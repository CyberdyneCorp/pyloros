## ADDED Requirements

### Requirement: List active sessions for an IAM role

An authorized operator SHALL be able to retrieve the active sessions for one role from the selected IAM provider.

#### Scenario: Active sessions

- **WHEN** the selected role has active, unexpired sessions
- **THEN** return their session, role and identity identifiers, start and expiry times, active flags and a total equal to the number returned

#### Scenario: Empty session inventory

- **WHEN** the role exists and the provider reports no current sessions
- **THEN** return an empty list and a total of zero

#### Scenario: Unknown role

- **WHEN** the selected provider has no role with the requested identifier
- **THEN** report that the role was not found
