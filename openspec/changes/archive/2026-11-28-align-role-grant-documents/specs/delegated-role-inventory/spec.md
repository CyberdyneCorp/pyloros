## ADDED Requirements

### Requirement: Decode numeric values in role grant documents
Operator and delegated user role grants SHALL apply the IAM document rules before checking credentials. Unused non-finite numeric fields SHALL be ignored after parsing. An integer exceeding 4,300 decimal digits SHALL produce HTTP 400 before a grant is recorded.

#### Scenario: Extra numeric metadata
- **WHEN** an authorized caller submits a valid assignment and an unrelated field containing a non-finite numeric literal
- **THEN** grant the role using the supplied assignment fields

#### Scenario: Invalid assignment field
- **WHEN** a field validation error would include a non-finite number in the response
- **THEN** return the unhandled HTTP 500 response and leave the assignment unchanged
