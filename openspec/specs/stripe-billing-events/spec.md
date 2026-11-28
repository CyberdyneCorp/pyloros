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

### Requirement: Match reversals after a repeat purchase
A second signed checkout for the same account, product and plan SHALL retain the existing entitlement ID and replace its external reference when the checkout supplies one. A checkout SHALL prefer its nonempty subscription ID over its payment intent. Subscription cancellation SHALL use the subscription object's ID when present and nonempty.

#### Scenario: Earlier purchase is reversed
- **WHEN** a refund or cancellation references the earlier purchase after the grant has moved to a new reference and no remaining grant matches the earlier one
- **THEN** defer the event with reason `no entitlement for reference` and preserve the current grant
- **AND** replaying the already processed earlier checkout SHALL preserve the current reference

#### Scenario: Current purchase is reversed
- **WHEN** replicas receive the same full refund or cancellation for the current reference
- **THEN** revoke the existing entitlement and mark that event processed once

### Requirement: Acknowledge independent events during entitlement writes
An informational invoice or partial refund with a distinct event ID SHALL be able to complete while another transaction holds the same billing reference for an entitlement write. Grants and revocations for that reference SHALL continue to serialize. Every processed event ID SHALL remain idempotent.

#### Scenario: Invoice arrives while checkout is in progress
- **WHEN** checkout holds a subscription reference and an invoice.created event for that subscription arrives
- **THEN** the invoice can commit as processed with handled false before checkout completes

#### Scenario: Partial and full refunds during purchase
- **WHEN** a purchase holds a payment reference and both a partial and a full refund arrive with distinct event IDs
- **THEN** the partial refund can commit with handled true before the purchase finishes and the full refund waits to reconcile the grant
- **AND** a replay of the processed partial refund returns handled false

### Requirement: Capture a large deferred-event inventory

The operator report SHALL emit the complete ordered JSON array from one database snapshot using memory bounded independently of the row count. A database read failure SHALL exit unsuccessfully with no report on standard output.

#### Scenario: The inventory spans multiple fetches

- **WHEN** the number of committed deferred events exceeds one fetch batch
- **THEN** include each matching event once in event ID order, including events whose reason is null

#### Scenario: A later fetch fails

- **WHEN** the database fails after some events were read
- **THEN** return an error and discard the partial report

### Requirement: Resolve historical checkout account identifiers
For a signed grant event with an explicit account reference, the service SHALL recognize legacy UUID spellings before checking the account and its customer mapping.

#### Scenario: Historical spelling identifies an existing account
- **WHEN** the reference uses compact hex inside braces, nonstandard hyphen placement, a lowercase UUID URN with compact hex, or Unicode decimal digits in the hex value
- **THEN** resolve the same account as the canonical UUID and apply the ordinary grant and replay rules

#### Scenario: Invalid explicit subject
- **WHEN** the explicit reference uses an uppercase URN scheme, is truncated, or contains a non-hexadecimal letter
- **THEN** defer the event as an unmapped customer and leave ownership and entitlements unchanged

### Requirement: Preserve billing ownership across account erasure
A committed account erasure SHALL remove its Stripe customer mapping and entitlements while preserving processed event IDs. A new account registered with the same email SHALL start without the erased account's access.

#### Scenario: A subscription update arrives after erasure
- **WHEN** a subscription update identifies only the former Stripe customer
- **THEN** defer it with the reason `unmapped customer`
- **AND** replaying an already processed checkout leaves the customer unmapped

#### Scenario: A checkout establishes a replacement mapping
- **WHEN** a fresh signed checkout maps the customer to the replacement account UUID and the deferred update is redelivered
- **THEN** apply the subscription plan to the replacement account and treat subsequent delivery of the same processed update as a replay

#### Scenario: PostgreSQL rejects the account deletion at commit
- **WHEN** the erasure transaction rolls back
- **THEN** the original customer mapping and entitlement remain available and a subsequent renewal applies to the original account
