## ADDED Requirements

### Requirement: Decode Unicode JSON for passkey login
The service SHALL decode supported UTF-8, UTF-16 and UTF-32 verification documents within the existing request byte limit.

#### Scenario: Encoded verification request
- **WHEN** a caller submits a validly encoded proof
- **THEN** apply the ordinary ceremony, binding and signature checks

#### Scenario: Invalid text
- **WHEN** a JSON body cannot be decoded as Unicode
- **THEN** return the HTTP 400 body-parsing problem
