## ADDED Requirements

### Requirement: Decode email verification requests

The service SHALL accept a JSON object containing a string token in UTF-8, UTF-16 or UTF-32 and SHALL retain the submitted value in field validation errors.

#### Scenario: Token is an object

- **WHEN** a client supplies a nested object as the verification token
- **THEN** return a field validation error containing the original object and its integer values before opening the redemption transaction.

#### Scenario: Additional fields

- **WHEN** a client supplies a string token with unrelated JSON fields
- **THEN** ignore the unrelated fields when validating the token and continue to redemption.
