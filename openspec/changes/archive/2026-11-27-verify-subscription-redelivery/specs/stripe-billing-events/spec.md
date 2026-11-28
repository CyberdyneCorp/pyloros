## ADDED Requirements

### Requirement: Resume subscription changes across a writer handoff
The service SHALL use committed customer mappings and billing event records after a PostgreSQL writer handoff to apply a previously deferred subscription change on redelivery. A processed event replay SHALL produce no further entitlement or hook changes.

#### Scenario: An upgrade precedes customer mapping
- **WHEN** checkout maps a customer after its upgrade was deferred, and the upgrade is redelivered to the new writer
- **THEN** the old subscription plan is revoked and the upgraded plan carries the supplied expiry
- **AND** refunding an independent purchase preserves that subscription until cancellation

#### Scenario: An informational invoice arrives
- **WHEN** a signed invoice.created notification is delivered
- **THEN** record the event as processed, report handled as false and preserve the grants
