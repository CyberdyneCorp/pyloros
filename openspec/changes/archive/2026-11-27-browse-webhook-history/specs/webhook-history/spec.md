## ADDED Requirements

### Requirement: Review webhook subscriptions and deliveries
The service SHALL authorize first-party administrators before returning subscription metadata or delivery attempts.

#### Scenario: Inspect subscription settings
- **WHEN** an administrator opens the directory or selects a subscription
- **THEN** return destination settings and current secret rotation status while keeping signing material private

#### Scenario: Read delivery history
- **WHEN** an administrator requests a subscription's history
- **THEN** return its newest deliveries first with an optional status filter, page totals, stable webhook message identifiers and attempts in chronological order

#### Scenario: Inspect a completed delivery
- **WHEN** the delivery is terminal
- **THEN** include the last status and error and return a null next-attempt time
