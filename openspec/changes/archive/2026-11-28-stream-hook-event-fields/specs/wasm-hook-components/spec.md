## ADDED Requirements

### Requirement: Read selected fields from wide hook events
The compiled event-name and counter examples SHALL handle supported event objects with thousands of unrelated fields within the worker's existing input and execution limits. The selected field's value SHALL be the last occurrence of its decoded key.

#### Scenario: Ascending unrelated keys
- **WHEN** a valid event contains 5,800 distinct ascending unrelated fields alongside a supported event type and count
- **THEN** each example returns its normal output for the selected field

#### Scenario: Escaped duplicate
- **WHEN** the selected field occurs again using an equivalent escaped key
- **THEN** use the later value and consume the rest of the document
