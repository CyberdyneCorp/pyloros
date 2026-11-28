# stripe-billing-events Specification

## Purpose
Define how verified Stripe notifications update access and schedule entitlement hook delivery.

## Requirements

### Requirement: Project verified Stripe events into entitlements
The service SHALL verify Stripe signatures against the original payload and apply supported billing events exactly once per processed event identifier.

#### Scenario: Complete a purchase
- **WHEN** a verified purchase identifies a user and an eligible product
- **THEN** activate the entitlement, associate its billing reference and record the event as processed

#### Scenario: Concurrent delivery survives a rejected commit
- **WHEN** two replicas receive the same signed checkout or refund and PostgreSQL rejects the first transaction at commit
- **THEN** the first request returns HTTP 500 and its entitlement change and hook delivery roll back
- **AND** the waiting request can apply the event and return HTTP 200 with `handled: true`
- **AND** later deliveries of that event return `handled: false` and leave the committed entitlement and hook execution count unchanged

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

### Requirement: Select subscription metadata and expiry
For subscription grants, the service SHALL use the product and optional plan from the first item's price metadata when that metadata identifies a product. Otherwise it SHALL use subscription metadata. The service SHALL prefer the subscription's integer period end, then the first item's integer period end, and otherwise store a null expiry.

#### Scenario: Subscription and item supply different dates
- **WHEN** both dates are integers and the first item's price metadata identifies a product
- **THEN** use the subscription date and the item's product and optional plan

#### Scenario: Item supplies the only integer date
- **WHEN** the subscription date is absent or nonintegral and the first item supplies an integer date
- **THEN** use the first item's date, including when the product comes from subscription metadata

#### Scenario: A later item supplies a date
- **WHEN** neither the subscription nor the first item supplies an integer date
- **THEN** leave the expiry null even if a subsequent item supplies a date

### Requirement: Sample webhook routing during cutover
An operator SHALL be able to sample the webhook ingress without a signing key. For each request the probe SHALL report whether the handler refused the unsigned payload and whether the ingress-reported upstream belongs to the expected pool.

#### Scenario: The previous pool still serves a request
- **WHEN** the response has the expected invalid-signature error but identifies an upstream outside the selected pool
- **THEN** report the sample as failed and return an unsuccessful exit status

#### Scenario: Ingress omits the upstream
- **WHEN** the response omits the configured upstream identifier
- **THEN** report the sample as failed even if the handler refused the unsigned payload

### Requirement: Reconcile refunds received before checkout
A full refund for a payment with no entitlement SHALL remain eligible for redelivery. The operator report SHALL list committed deferred event IDs and reasons in event ID order and exit 2 when any are present, or 0 when empty.

#### Scenario: Refund commits before checkout
- **WHEN** a full refund is received before checkout grants access for its payment reference
- **THEN** acknowledge the refund with handled false and list the deferred event
- **AND** after checkout, redelivery of that refund revokes the grant once and removes the event from the report

#### Scenario: Checkout commits before refund
- **WHEN** checkout grants access before its full refund is processed
- **THEN** both events are processed and the entitlement is revoked
- **AND** later replays preserve the revoked state and neither event appears in the report

### Requirement: Serialize first-time customer claims
When signed checkouts name the same unmapped customer and different accounts, the first committed mapping SHALL establish ownership. A checkout SHALL grant access only when its product is eligible. A conflicting claim SHALL remain deferred with the reason `customer belongs to another user` on redelivery while that mapping exists.

#### Scenario: First claim commits
- **WHEN** two replicas process distinct, otherwise eligible checkouts for one customer
- **THEN** the first committed grant is handled, the conflicting event is acknowledged with handled false, and exactly one account receives access

#### Scenario: First claim rolls back
- **WHEN** the first checkout reaches commit and PostgreSQL rejects it while the other checkout is waiting
- **THEN** the first request returns HTTP 500 with no committed ledger entry and the waiting checkout may claim the customer
- **AND** redelivering the first event after the other claim commits records the conflict without changing ownership

#### Scenario: Customer mapped while the catalog entry is unavailable
- **WHEN** a signed checkout supplies a product key and a valid account for a new customer, but the product is missing or inactive
- **THEN** commit the customer mapping and deferred event without granting access
- **AND** once the product is eligible, concurrent redeliveries of that event SHALL apply its grant once to the mapped account

#### Scenario: No product key supplied
- **WHEN** a checkout omits the product metadata required for a grant
- **THEN** defer it without establishing a customer mapping
- **AND** another eligible checkout may claim that customer while the original event remains deferred
