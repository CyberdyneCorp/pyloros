## ADDED Requirements

### Requirement: Validate password recovery documents

The service SHALL decode UTF-8, UTF-16 and UTF-32 JSON on both password recovery routes. It SHALL report each invalid field with the submitted value and each missing field with the containing object.

#### Scenario: Multiple invalid confirmation fields

- **WHEN** a client supplies a token of the wrong type and omits the replacement password
- **THEN** return both field errors in schema order and preserve the exact integer values in each error's input.

#### Scenario: Additional fields in recovery requests

- **WHEN** a client requests recovery using a JSON object with an email and unrelated fields
- **THEN** validate the email independently of the unrelated fields before applying the recovery quota.
