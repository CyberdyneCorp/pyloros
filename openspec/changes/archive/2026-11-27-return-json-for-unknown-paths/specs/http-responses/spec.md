## ADDED Requirements

### Requirement: Unknown URLs return the standard error representation
The HTTP router SHALL return the JSON Not Found problem with status 404 for unmatched URLs, including URLs whose trailing-slash variant is also unknown.

#### Scenario: Request an unknown URL
- **WHEN** a caller requests an unknown path
- **THEN** return the JSON error with type about:blank, status 404, and title and detail Not Found

#### Scenario: Request only the headers
- **WHEN** a caller sends HEAD to an unknown path
- **THEN** return 404 with the JSON content type and an empty response body
