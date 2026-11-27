## ADDED Requirements

### Requirement: Deliver committed account registrations
The service SHALL queue registration events for accounts created by self-registration, administrator creation, CSV import or service-client invitation when registration dispatch is enabled.

#### Scenario: Per-recipient privacy
- **WHEN** a new account commits
- **THEN** deliver its user id and event type to each selected active hook, adding normalized email and public wallet address only for recipients opted in at enqueue and execution

#### Scenario: Existing or rolled back account
- **WHEN** a request creates no account or its transaction rolls back
- **THEN** produce no registration delivery
