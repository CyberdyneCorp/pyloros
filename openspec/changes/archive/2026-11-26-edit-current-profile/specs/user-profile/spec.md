## ADDED Requirements

### Requirement: Edit own phone
PATCH /api/v1/users/me SHALL accept a first-party user credential and a JSON object with an optional nullable phone string. Supplying a string SHALL clear phone verification. An empty string SHALL remove the phone. The response SHALL include the current profile with null role fields.

#### Scenario: Phone changes
- **WHEN** the stored phone changes
- **THEN** the service commits the edit and a subject rectification audit event together, recording the field name without its value

#### Scenario: No phone supplied
- **WHEN** the phone is absent or null
- **THEN** the service preserves the phone and its verification state

#### Scenario: OAuth client credential
- **WHEN** a client-bound access credential is presented
- **THEN** the service returns the unauthenticated challenge
