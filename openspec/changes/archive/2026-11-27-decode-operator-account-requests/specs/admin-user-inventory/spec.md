## ADDED Requirements

### Requirement: Decode operator account creation requests
Operator account creation SHALL accept Unicode JSON credential documents, including those with ignored properties exceeding two MiB. Syntax errors SHALL precede operator authentication and credential field errors SHALL follow authorization.

#### Scenario: Anonymous caller submits valid JSON with invalid fields
- **WHEN** an anonymous caller submits a numeric email field in a syntactically valid request
- **THEN** return the authentication challenge

#### Scenario: Operator submits a Unicode document
- **WHEN** an authorized operator submits a valid address and password in UTF-16 or UTF-32 JSON
- **THEN** provision the verified account and commit the account and operator audit records
