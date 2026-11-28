## ADDED Requirements

### Requirement: Preserve displayed erasure context order
A deletion hook SHALL receive the event type first and the erased user ID second. These two fields form its complete context at either privacy setting.

#### Scenario: Read execution history after deletion
- **WHEN** a component prints the context of a committed account deletion
- **THEN** its execution history shows the event type followed by the erased subject identifier
