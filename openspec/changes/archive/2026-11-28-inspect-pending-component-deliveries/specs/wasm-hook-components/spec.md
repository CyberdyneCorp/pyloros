## ADDED Requirements

### Requirement: Inspect pending component deliveries
Operators SHALL be able to read the committed pending delivery count for all events or any set of supported event names. The check SHALL emit a JSON object containing only the pending count and exit with 0 for an empty selection result or 2 for remaining work. Invalid event names and unreadable or missing queue storage SHALL fail without emitting a count.

#### Scenario: Check while the worker is draining
- **WHEN** a selected delivery is delayed or a worker has claimed it without committing removal
- **THEN** include the row once, including when an event name repeats
- **AND** exclude the row once removal commits

#### Scenario: Other producers keep working
- **WHEN** only unrelated deliveries remain
- **THEN** report zero for the selected event types
