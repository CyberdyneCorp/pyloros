## ADDED Requirements

### Requirement: Match reversals after a repeat purchase
A second signed checkout for the same account, product and plan SHALL retain the existing entitlement ID and replace its external reference when the checkout supplies one. A checkout SHALL prefer its nonempty subscription ID over its payment intent. Subscription cancellation SHALL use the subscription object's ID when present and nonempty.

#### Scenario: Earlier purchase is reversed
- **WHEN** a refund or cancellation references the earlier purchase after the grant has moved to a new reference and no remaining grant matches the earlier one
- **THEN** defer the event with reason `no entitlement for reference` and preserve the current grant
- **AND** replaying the already processed earlier checkout SHALL preserve the current reference

#### Scenario: Current purchase is reversed
- **WHEN** replicas receive the same full refund or cancellation for the current reference
- **THEN** revoke the existing entitlement and mark that event processed once
