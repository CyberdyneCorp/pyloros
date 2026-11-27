## ADDED Requirements

### Requirement: Deliver completed interactive login events
When interactive login dispatch is enabled, the service SHALL enqueue one event per active bound recipient in the same transaction as a new interactive session.

#### Scenario: Completed login
- **WHEN** password, passkey, or second-factor verification completes interactive login
- **THEN** each recipient receives the event type and user ID, with email, IP and user agent only for recipients opted in at enqueue and execution

#### Scenario: Login does not commit
- **WHEN** login fails, awaits a second factor, or its session transaction rolls back
- **THEN** the worker receives no event from that attempt
