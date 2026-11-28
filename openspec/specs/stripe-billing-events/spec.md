# stripe-billing-events Specification

## Purpose
Define how verified Stripe notifications update access and schedule entitlement hook delivery.

## Requirements

### Requirement: Project verified Stripe events into entitlements
The service SHALL verify Stripe signatures against the original payload and apply supported billing events exactly once per processed event identifier.

#### Scenario: Complete a purchase
- **WHEN** a verified purchase identifies a user and an eligible product
- **THEN** activate the entitlement, associate its billing reference and record the event as processed

#### Scenario: Change or revoke a subscription
- **WHEN** a verified subscription changes plans or is cancelled
- **THEN** retire superseded access or revoke the active grants for that billing reference

#### Scenario: Retry a deferred event
- **WHEN** an otherwise valid notification arrives before its customer or product can be resolved
- **THEN** record the deferral and permit the same event to be applied on redelivery

#### Scenario: Reject an invalid signature
- **WHEN** the signing header is absent, invalid or stale
- **THEN** reject the notification before changing the billing ledger

#### Scenario: Preserve customer ownership
- **WHEN** the signed checkout identifies a different user from the stored customer mapping
- **THEN** defer the event and preserve the existing customer and entitlement records

#### Scenario: Keep an unfulfilled callback retryable
- **WHEN** hook processing is enabled and an active hook cannot accept delivery because its component version or store dispatcher is unconfigured
- **THEN** roll back the event, return a retryable error and preserve eligibility for redelivery

#### Scenario: Recover after component execution becomes available
- **WHEN** an event has committed a delivery that cannot yet start its worker
- **THEN** retain the selected version and retry execution independently of provider redelivery

### Requirement: Resume subscription changes across a writer handoff
The service SHALL use committed customer mappings and billing event records after a PostgreSQL writer handoff to apply a previously deferred subscription change on redelivery. A processed event replay SHALL produce no further entitlement or hook changes.

#### Scenario: An upgrade precedes customer mapping
- **WHEN** checkout maps a customer after its upgrade was deferred, and the upgrade is redelivered to the new writer
- **THEN** the old subscription plan is revoked and the upgraded plan carries the supplied expiry
- **AND** refunding an independent purchase preserves that subscription until cancellation

#### Scenario: An informational invoice arrives
- **WHEN** a signed invoice.created notification is delivered
- **THEN** record the event as processed, report handled as false and preserve the grants
