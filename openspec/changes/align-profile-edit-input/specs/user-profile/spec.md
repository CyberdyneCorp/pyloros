## ADDED Requirements

### Requirement: Profile edit input compatibility

The service SHALL process profile update requests in UTF-8, UTF-16 and UTF-32. Invalid encodings and malformed JSON SHALL return request errors before account access checks.

#### Scenario: Invalid field type

- **WHEN** an authenticated user submits a non-string, non-null phone
- **THEN** return a validation error identifying the field and its submitted value.

#### Scenario: Unrelated profile fields

- **WHEN** an authenticated user submits a valid object containing only unrelated fields
- **THEN** return the current profile with the stored phone and verification state intact.

#### Scenario: Overlapping edits

- **WHEN** two requests both read the old phone before either writes the same new phone
- **THEN** each committed edit records a rectification event. A later sequential request setting the stored value adds no event.
