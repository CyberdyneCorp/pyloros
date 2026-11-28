## ADDED Requirements

### Requirement: Select webhook recipients on each role change
With webhooks enabled, an operator or delegated client role mutation that emits an event SHALL persist a single event shared by one delivery per active subscription matching its type. When none match, the mutation SHALL commit its role and audit effects without creating an event or delivery.

#### Scenario: Filter changes before a repeated grant
- **WHEN** two subscriptions match a grant, one switches to revocations, and a writer repeats the grant
- **THEN** the first event retains both delivery records and the new event has only the remaining grant subscriber, with one assigned role and an audit entry for each grant

#### Scenario: Subscriptions are disabled between writes
- **WHEN** the grant subscriber is disabled, the role is revoked, and the revocation subscriber is disabled before the next grant
- **THEN** the revocation has one delivery to its subscriber and the next grant succeeds without creating a webhook event
