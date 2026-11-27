## ADDED Requirements

### Requirement: Manage subscription destinations
The service SHALL permit administrators to create and edit uniquely named webhook subscriptions with validated destinations and event selections.

#### Scenario: Create a subscription
- **WHEN** an administrator registers a valid destination
- **THEN** the service returns the created subscription and its generated signing secret and records the creation in the audit history

#### Scenario: Edit selected properties
- **WHEN** an administrator edits a subscription
- **THEN** the service preserves omitted properties, records the supplied fields and returns the updated subscription without exposing signing material
