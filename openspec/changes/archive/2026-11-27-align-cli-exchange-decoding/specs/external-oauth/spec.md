## ADDED Requirements

### Requirement: Decode CLI exchange documents before selecting the feature response
The service SHALL accept UTF-8, UTF-16 and UTF-32 JSON exchange documents, including documents with padding beyond two MiB, and ignore unrelated fields.

#### Scenario: Exchange disabled
- **WHEN** a validly shaped exchange arrives while CLI login is disabled
- **THEN** return the disabled-login problem regardless of JSON encoding

#### Scenario: Unreadable request
- **WHEN** the submitted JSON bytes cannot be decoded as text
- **THEN** return the HTTP 400 body-parsing problem

#### Scenario: Malformed JSON or invalid fields
- **WHEN** the text is malformed JSON or the submitted fields fail exchange validation
- **THEN** return the HTTP 400 invalid_grant response
