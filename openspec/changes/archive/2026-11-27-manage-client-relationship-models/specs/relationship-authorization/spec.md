## ADDED Requirements

### Requirement: Manage the calling application’s relationship model
PUT /api/v1/clients/me/rebac/model SHALL accept a service credential explicitly granted rebac:manage. A successful replacement SHALL return 204 and preserve existing relationships.

#### Scenario: Invalid permission path
- **WHEN** a model references a missing relation, object type or target permission
- **THEN** reject it without changing the stored model

#### Scenario: Existing data conflicts
- **WHEN** an updated model would invalidate a stored assignment
- **THEN** return 409 and preserve the previous model

#### Scenario: Audited changes
- **WHEN** the model changes
- **THEN** commit the calling client’s model and audit entry together, and allow an identical retry without another change record

#### Scenario: Model exceeds the validation budget
- **WHEN** the proposed permission rules require more than 65,536 reference checks
- **THEN** return 422 and preserve the current model
