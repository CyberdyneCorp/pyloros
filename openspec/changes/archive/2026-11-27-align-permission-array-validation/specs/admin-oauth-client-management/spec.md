## ADDED Requirements

### Requirement: Match IAM numeric handling during role mapping replacement
Both role permission replacement routes SHALL apply the IAM numeric input rules and preserve the current mapping when parsing or validation fails.

#### Scenario: Integer exceeds decoder capacity
- **WHEN** a caller submits a mapping document containing an integer with more than 4300 decimal digits, even in an ignored field
- **THEN** respond with a body parsing error and retain the prior permission set

#### Scenario: Non-finite value outside the permission list
- **WHEN** an authorized caller submits valid permissions and an unrelated field containing a non-finite number
- **THEN** apply the requested permission set

#### Scenario: Non-finite value in a validation diagnostic
- **WHEN** producing the validation diagnostic would require returning a non-finite value in the error body
- **THEN** return the unhandled error response and retain the prior permission set
