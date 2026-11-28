## ADDED Requirements

### Requirement: Capture a large deferred-event inventory

The operator report SHALL emit the complete ordered JSON array from one database snapshot using memory bounded independently of the row count. A database read failure SHALL exit unsuccessfully with no report on standard output.

#### Scenario: The inventory spans multiple fetches

- **WHEN** the number of committed deferred events exceeds one fetch batch
- **THEN** include each matching event once in event ID order, including events whose reason is null

#### Scenario: A later fetch fails

- **WHEN** the database fails after some events were read
- **THEN** return an error and discard the partial report
