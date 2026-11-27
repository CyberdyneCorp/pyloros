## ADDED Requirements

### Requirement: Decode Unicode registration documents
The public account registration endpoint SHALL accept UTF-8, UTF-16 and UTF-32 JSON and validate the submitted email and password, including when ignored fields make the document larger than two MiB.

#### Scenario: Wide document with unknown properties
- **WHEN** an available address and valid password are submitted in UTF-32 JSON with additional fields
- **THEN** create the account and issue its verification email through the configured delivery provider

#### Scenario: Incorrect field type
- **WHEN** a registration document supplies a finite numeric email
- **THEN** include the original number in the field validation response
