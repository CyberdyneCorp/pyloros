## ADDED Requirements

### Requirement: Read authenticator enrollment
The MFA status endpoint SHALL report whether the authenticated first-party account has an enabled authenticator and how many unused recovery codes remain.

#### Scenario: Enrolled account
- **WHEN** a first-party caller reads its enrollment
- **THEN** return its enrollment flag and count only its own unused codes.

#### Scenario: Disabled authenticator
- **WHEN** the authenticator is disabled or setup is pending
- **THEN** return a disabled status and zero remaining codes.

#### Scenario: OAuth access
- **WHEN** the credential belongs to an OAuth client
- **THEN** refuse access to the enrollment status.
