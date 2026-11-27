## MODIFIED Requirements

### Requirement: First-party session input decoding

The service SHALL decode supported JSON encodings before validating credentials and SHALL preserve submitted values in field errors for sign-in, MFA verification, refresh and logout.

#### Scenario: UTF-16 refresh request

- **WHEN** a UTF-16 JSON document supplies a numeric refresh token
- **THEN** validation identifies the refresh token as an invalid string and returns its submitted value

#### Scenario: Unsupported request media

- **WHEN** a session operation receives a nonempty plain-text or URL-encoded body
- **THEN** it returns the compatible internal error response without issuing credentials

#### Scenario: Large encoded session document
- **WHEN** a valid credential is supplied in a multi-megabyte JSON request with unrelated fields
- **THEN** perform the requested session operation with the same validation and state effects as a compact document

#### Scenario: Numeric credential
- **WHEN** a credential field contains an integer with hundreds of digits
- **THEN** return the string-field validation error with the submitted integer and preserve session state
