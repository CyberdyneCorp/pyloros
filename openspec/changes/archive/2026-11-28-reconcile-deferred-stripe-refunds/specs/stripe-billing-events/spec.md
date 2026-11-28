## ADDED Requirements

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
