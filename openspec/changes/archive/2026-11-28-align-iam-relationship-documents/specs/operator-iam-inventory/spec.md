## ADDED Requirements

### Requirement: Decode operator IAM relationship requests
Group policy attachment, user group membership, direct user policy attachment and identity boundary assignment SHALL apply IAM document decoding before operator authentication.

#### Scenario: An extension field contains a non-finite number
- **WHEN** an authorized operator submits a valid relationship identifier and a non-finite literal in an unused field
- **THEN** apply the relationship and record the operator action

#### Scenario: Integer exceeds the document limit
- **WHEN** any integer literal in the submitted document exceeds 4,300 digits
- **THEN** return HTTP 400 without modifying the relationship or appending its audit entry

#### Scenario: A non-finite number is supplied as the identifier
- **WHEN** rendering the identifier validation error would include a non-finite number
- **THEN** return the unhandled HTTP 500 response and preserve the stored relationship
