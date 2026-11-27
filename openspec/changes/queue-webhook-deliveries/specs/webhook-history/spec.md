## ADDED Requirements

### Requirement: Queue webhook tests and retries
Pyloros SHALL authorize first-party administrators before changing webhook delivery state and SHALL audit successful queue actions.

#### Scenario: Test one active destination
- **WHEN** an administrator requests a test for an active subscription
- **THEN** enqueue one webhook.test message for that subscription and return HTTP 202 with the message identifier

#### Scenario: Retry a completed delivery
- **WHEN** an administrator retries a finished delivery on an active subscription
- **THEN** reset its retry budget, make it due immediately, and preserve the event identifier, signed body and prior attempt history

#### Scenario: Refuse a conflicting queue action
- **WHEN** an administrator retries a pending delivery or requests a delivery for an inactive subscription
- **THEN** return HTTP 409 without adding a queue entry or changing its retry budget
