## ADDED Requirements

### Requirement: Preserve numeric input behavior for email verification and password recovery
Requests for email verification and password recovery SHALL accept Unicode JSON, validate the scalar fields used by the operation and ignore unrelated values after document decoding.

#### Scenario: Unused numeric input
- **WHEN** a valid credential is accompanied by a non-finite value in an unused field
- **THEN** proceed with normal credential handling

#### Scenario: Unrepresentable validation error
- **WHEN** a validation error would include a non-finite number in its JSON response
- **THEN** return the unhandled server error response
